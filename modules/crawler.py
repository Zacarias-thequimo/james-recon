from __future__ import annotations

import re
import asyncio
from urllib.parse import urljoin, urlparse

import httpx

from core.module import BaseModule
from core.target import Target, FuzzResult

UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"


class Crawler(BaseModule):
    name = "crawler"
    description = "Spider/crawler que descobre páginas, APIs, JS bundles e paths ocultos"

    def __init__(self, max_pages: int = 50, concurrency: int = 10):
        self.max_pages = max_pages
        self.concurrency = concurrency

    async def run(self, target: Target) -> Target:
        base = f"https://{target.domain}"
        visited: set[str] = set()
        to_visit: set[str] = {"/"}
        discovered: list[FuzzResult] = list(target.fuzz_results)
        js_files: list[str] = []
        api_endpoints: list[str] = []
        sem = asyncio.Semaphore(self.concurrency)

        async with httpx.AsyncClient(
            timeout=10, follow_redirects=True, verify=False,
            headers={"User-Agent": UA},
        ) as client:
            while to_visit and len(visited) < self.max_pages:
                batch = list(to_visit)[:self.concurrency]
                to_visit -= set(batch)

                async def fetch(path: str):
                    async with sem:
                        if path in visited:
                            return
                        visited.add(path)
                        url = f"{base}{path}" if path.startswith("/") else path
                        try:
                            resp = await client.get(url)
                            return path, resp
                        except Exception:
                            return None

                results = await asyncio.gather(*(fetch(p) for p in batch))

                for r in results:
                    if r is None:
                        continue
                    path, resp = r

                    # Record result
                    if not any(f.url == path for f in discovered):
                        discovered.append(FuzzResult(url=path, status=resp.status_code, length=len(resp.text)))

                    if resp.status_code != 200:
                        continue

                    ct = resp.headers.get("content-type", "")
                    if "html" not in ct:
                        continue

                    html = resp.text

                    # Extract links
                    for href in re.findall(r'href=["\']([^"\'#]+)["\']', html, re.I):
                        new_path = self._normalize(href, path, target.domain)
                        if new_path and new_path not in visited:
                            to_visit.add(new_path)

                    # Extract JS files
                    for src in re.findall(r'src=["\']([^"\']+\.js[^"\']*)["\']', html, re.I):
                        if src not in js_files:
                            js_files.append(src)

                    # Extract API endpoints from JS/HTML
                    for match in re.findall(r'["\'](/api/[^"\']+)["\']', html, re.I):
                        if match not in api_endpoints:
                            api_endpoints.append(match)

            # Analyze JS bundles for API endpoints
            for js_url in js_files[:15]:
                if js_url.startswith("/"):
                    full_url = f"{base}{js_url}"
                elif js_url.startswith("http"):
                    full_url = js_url
                else:
                    full_url = f"{base}/{js_url}"

                try:
                    resp = await client.get(full_url)
                    if resp.status_code == 200:
                        # Find API paths in JS
                        for match in re.findall(r'["\'](/api/[^"\']+)["\']', resp.text):
                            if match not in api_endpoints:
                                api_endpoints.append(match)
                        # Find fetch/axios URLs
                        for match in re.findall(r'(?:fetch|axios|\.get|\.post)\s*\(\s*["\']([^"\']+)["\']', resp.text, re.I):
                            if match.startswith("/") and match not in api_endpoints:
                                api_endpoints.append(match)
                except Exception:
                    continue

            # Probe discovered API endpoints
            for ep in api_endpoints[:30]:
                if ep in visited:
                    continue
                try:
                    resp = await client.get(f"{base}{ep}")
                    if not any(f.url == ep for f in discovered):
                        discovered.append(FuzzResult(url=ep, status=resp.status_code, length=len(resp.text)))
                except Exception:
                    pass

        # Store results
        target.fuzz_results = sorted(discovered, key=lambda f: (f.status, f.url))

        # Add tech info
        if js_files:
            target.technologies["js_bundles"] = str(len(js_files))
        if api_endpoints:
            target.technologies["api_endpoints_found"] = str(len(api_endpoints))

        return target

    def _normalize(self, href: str, current_path: str, domain: str) -> str | None:
        """Normalize href to a path on the same domain, or None if external."""
        if href.startswith(("mailto:", "tel:", "javascript:", "data:", "#")):
            return None
        if href.startswith("http"):
            parsed = urlparse(href)
            if parsed.hostname and domain not in parsed.hostname:
                return None
            return parsed.path or "/"
        if href.startswith("/"):
            return href.split("?")[0].split("#")[0]
        # Relative path
        base_dir = current_path.rsplit("/", 1)[0] if "/" in current_path else ""
        return f"{base_dir}/{href}".split("?")[0].split("#")[0]
