from __future__ import annotations

import httpx

from core.module import BaseModule
from core.target import Target

REQUIRED_HEADERS = {
    "strict-transport-security": "HSTS",
    "content-security-policy": "CSP",
    "x-frame-options": "X-Frame-Options",
    "x-content-type-options": "X-Content-Type-Options",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy",
    "x-xss-protection": "X-XSS-Protection",
}

INFO_LEAK_HEADERS = ["server", "x-powered-by", "x-aspnet-version", "x-generator", "x-debug"]


class HeadersCheck(BaseModule):
    name = "headers_check"
    description = "Auditoria de security headers, info leak e CORS"

    async def run(self, target: Target) -> Target:
        sec_headers: dict = {}
        cors_issues: list[dict] = []

        for scheme in ("https", "http"):
            url = f"{scheme}://{target.domain}"
            try:
                async with httpx.AsyncClient(timeout=10, follow_redirects=True, verify=False) as c:
                    resp = await c.get(url)

                # Security headers
                present = {}
                missing = []
                for hdr, label in REQUIRED_HEADERS.items():
                    val = resp.headers.get(hdr)
                    if val:
                        present[label] = val
                    else:
                        missing.append(label)

                sec_headers["present"] = present
                sec_headers["missing"] = missing

                # Info leak
                leaks = {}
                for hdr in INFO_LEAK_HEADERS:
                    val = resp.headers.get(hdr)
                    if val:
                        leaks[hdr] = val
                sec_headers["info_leak"] = leaks

                # CSP analysis
                csp = resp.headers.get("content-security-policy", "")
                if csp:
                    csp_issues = []
                    if "unsafe-inline" in csp:
                        csp_issues.append("unsafe-inline permite XSS")
                    if "unsafe-eval" in csp:
                        csp_issues.append("unsafe-eval permite eval()")
                    if "default-src *" in csp or "default-src *" in csp:
                        csp_issues.append("default-src * permite qualquer origem")
                    if csp_issues:
                        sec_headers["csp_issues"] = csp_issues
                        target.vulns.append({
                            "type": "weak_csp",
                            "severity": "HIGH",
                            "detail": f"CSP fraco: {'; '.join(csp_issues)}",
                            "host": target.domain,
                        })

                if missing:
                    severity = "HIGH" if len(missing) >= 5 else "MEDIUM"
                    target.vulns.append({
                        "type": "missing_security_headers",
                        "severity": severity,
                        "detail": f"{len(missing)} headers ausentes: {', '.join(missing)}",
                        "host": target.domain,
                    })

                if leaks:
                    target.vulns.append({
                        "type": "info_leak_headers",
                        "severity": "LOW",
                        "detail": f"Headers expõem: {', '.join(f'{k}={v}' for k,v in leaks.items())}",
                        "host": target.domain,
                    })

                # CORS check
                await self._check_cors(c, target, cors_issues)

                break
            except Exception:
                continue

        target.security_headers = sec_headers
        target.cors_issues = cors_issues
        return target

    async def _check_cors(self, client: httpx.AsyncClient, target: Target, issues: list[dict]):
        hosts = [target.domain] + target.subdomains[:10]
        for host in hosts:
            for scheme in ("https", "http"):
                try:
                    resp = await client.get(
                        f"{scheme}://{host}/",
                        headers={"Origin": "https://evil.com"},
                        timeout=5,
                    )
                    acao = resp.headers.get("access-control-allow-origin", "")
                    acac = resp.headers.get("access-control-allow-credentials", "")
                    if acao in ("*", "https://evil.com"):
                        issue = {
                            "host": host,
                            "acao": acao,
                            "acac": acac,
                            "severity": "CRITICAL" if acac.lower() == "true" else "HIGH",
                        }
                        issues.append(issue)
                        target.vulns.append({
                            "type": "cors_wildcard",
                            "severity": issue["severity"],
                            "detail": f"CORS aceita origem arbitrária em {host} (ACAO={acao}, ACAC={acac})",
                            "host": host,
                        })
                    break
                except Exception:
                    continue
