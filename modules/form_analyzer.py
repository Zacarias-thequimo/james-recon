from __future__ import annotations

import re
import asyncio
import urllib.parse

import httpx

from core.module import BaseModule
from core.target import Target

UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"


class FormAnalyzer(BaseModule):
    name = "form_analyzer"
    description = "Descobre formulários, testa SQLi, XSS e analisa CSRF"

    async def run(self, target: Target) -> Target:
        forms: list[dict] = []
        sqli_results: list[dict] = []

        async with httpx.AsyncClient(
            timeout=15, follow_redirects=True, verify=False,
            headers={"User-Agent": UA},
        ) as client:
            # Collect pages to scan
            pages = ["/"]
            # Add fuzz results that returned 200
            for fr in target.fuzz_results:
                if fr.status == 200:
                    path = urllib.parse.urlparse(fr.url).path
                    if path and path not in pages:
                        pages.append(path)

            # Crawl pages for forms
            base = f"https://{target.domain}"
            for page in pages[:20]:
                url = f"{base}{page}" if page.startswith("/") else page
                try:
                    resp = await client.get(url)
                    page_forms = self._extract_forms(resp.text, url)
                    forms.extend(page_forms)
                except Exception:
                    continue

            # Test forms for SQLi
            for form in forms:
                results = await self._test_sqli(client, base, form)
                sqli_results.extend(results)

        target.forms = forms
        target.sqli_results = sqli_results
        return target

    def _extract_forms(self, html: str, page_url: str) -> list[dict]:
        forms = []
        form_blocks = re.findall(r'<form[^>]*>(.*?)</form>', html, re.I | re.S)
        form_tags = re.findall(r'<form([^>]*)>', html, re.I)

        for i, (tag_attrs, body) in enumerate(zip(form_tags, form_blocks)):
            action = re.findall(r'action=["\']([^"\']*)["\']', tag_attrs, re.I)
            method = re.findall(r'method=["\']([^"\']*)["\']', tag_attrs, re.I)

            inputs = []
            for inp in re.findall(r'<(?:input|textarea|select)[^>]*>', body, re.I):
                name = re.findall(r'name=["\']([^"\']+)["\']', inp, re.I)
                itype = re.findall(r'type=["\']([^"\']+)["\']', inp, re.I)
                if name:
                    inputs.append({
                        "name": name[0],
                        "type": itype[0] if itype else "text",
                    })

            has_csrf = bool(re.search(r'csrf|token|__RequestVerificationToken|__VIEWSTATE', body, re.I))

            form_info = {
                "page": page_url,
                "action": action[0] if action else "",
                "method": (method[0] if method else "GET").upper(),
                "inputs": inputs,
                "has_csrf": has_csrf,
            }

            if not has_csrf and inputs:
                # Only flag as vuln if there are actual submittable inputs
                text_inputs = [i for i in inputs if i["type"] not in ("hidden", "submit", "button")]
                if text_inputs:
                    pass  # CSRF missing is noted in form_info

            forms.append(form_info)

        return forms

    async def _test_sqli(self, client: httpx.AsyncClient, base_url: str, form: dict) -> list[dict]:
        results = []
        text_inputs = [i for i in form["inputs"] if i["type"] not in ("hidden", "submit", "button", "checkbox", "radio")]

        if not text_inputs:
            return results

        action = form["action"]
        if action and not action.startswith("http"):
            action = f"{base_url}/{action.lstrip('/')}"
        elif not action:
            action = form["page"]

        method = form["method"]

        for inp in text_inputs:
            param = inp["name"]

            # Get baseline
            normal_data = {inp["name"]: "test@test.com" for inp in text_inputs}
            try:
                if method == "POST":
                    bl_resp = await client.post(action, data=normal_data)
                else:
                    bl_resp = await client.get(action, params=normal_data)
                bl_size = len(bl_resp.text)
            except Exception:
                continue

            # Test single quote
            sqli_data = dict(normal_data)
            sqli_data[param] = "test'"
            try:
                if method == "POST":
                    sq_resp = await client.post(action, data=sqli_data)
                else:
                    sq_resp = await client.get(action, params=sqli_data)
                sq_size = len(sq_resp.text)
            except Exception:
                continue

            # Test balanced quotes
            balanced_data = dict(normal_data)
            balanced_data[param] = "test''test"
            try:
                if method == "POST":
                    bal_resp = await client.post(action, data=balanced_data)
                else:
                    bal_resp = await client.get(action, params=balanced_data)
                bal_size = len(bal_resp.text)
            except Exception:
                continue

            # Analysis: if single quote produces very different response but balanced doesn't
            sq_diff = abs(sq_size - bl_size)
            bal_diff = abs(bal_size - bl_size)

            # Check for SQL error strings
            sql_errors = [
                r'mysql', r'SQL syntax', r'SQLSTATE', r'PDOException',
                r'Warning.*mysql', r'pg_', r'sqlite', r'ORA-\d+',
                r'Query failed', r'You have an error',
            ]
            has_sql_error = any(re.search(p, sq_resp.text, re.I) for p in sql_errors)

            if has_sql_error:
                result = {
                    "type": "error_based",
                    "severity": "CRITICAL",
                    "url": action,
                    "method": method,
                    "param": param,
                    "detail": "Erro SQL visível na resposta com single quote",
                    "baseline_size": bl_size,
                    "sqli_size": sq_size,
                }
                results.append(result)
                target_vuln = dict(result)
                target_vuln["type"] = "sqli"
                continue

            # Boolean-based detection: quote breaks, balanced doesn't
            if sq_diff > bl_size * 0.5 and bal_diff < bl_size * 0.1:
                # Time-based confirmation
                sleep_confirmed = await self._test_sleep(client, action, method, normal_data, param)

                result = {
                    "type": "boolean_blind" + (" + time_based" if sleep_confirmed else ""),
                    "severity": "CRITICAL",
                    "url": action,
                    "method": method,
                    "param": param,
                    "detail": f"Single quote muda resposta ({bl_size}→{sq_size}), balanced quotes normal ({bal_size}). {'SLEEP confirmado.' if sleep_confirmed else ''}",
                    "baseline_size": bl_size,
                    "sqli_size": sq_size,
                    "balanced_size": bal_size,
                    "sleep_confirmed": sleep_confirmed,
                }
                results.append(result)

            elif sq_diff > 200:
                # Smaller difference — possible but not confirmed
                result = {
                    "type": "possible_sqli",
                    "severity": "MEDIUM",
                    "url": action,
                    "method": method,
                    "param": param,
                    "detail": f"Diferença com single quote: {sq_diff} bytes ({bl_size}→{sq_size})",
                    "baseline_size": bl_size,
                    "sqli_size": sq_size,
                }
                results.append(result)

        return results

    async def _test_sleep(self, client: httpx.AsyncClient, url: str, method: str,
                          base_data: dict, param: str) -> bool:
        """Test time-based blind SQLi with SLEEP"""
        import time

        for comment in (" #", " -- "):
            sleep_data = dict(base_data)
            sleep_data[param] = f"test' AND SLEEP(3){comment}"
            try:
                start = time.time()
                if method == "POST":
                    await client.post(url, data=sleep_data)
                else:
                    await client.get(url, params=sleep_data)
                elapsed = time.time() - start
                if elapsed >= 2.5:
                    return True
            except Exception:
                # Timeout can also indicate SLEEP worked
                return True

        return False
