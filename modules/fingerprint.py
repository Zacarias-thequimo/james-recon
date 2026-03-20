from __future__ import annotations

import re

import httpx

from core.module import BaseModule
from core.target import Target

HEADER_TECH = {
    "server": "Server",
    "x-powered-by": "Powered-By",
    "x-aspnet-version": "ASP.NET",
    "x-generator": "Generator",
}

HTML_PATTERNS: list[tuple[str, str]] = [
    (r"wp-content|wordpress", "WordPress"),
    (r"Joomla", "Joomla"),
    (r"Drupal", "Drupal"),
    (r"react", "React"),
    (r"vue\.js|vuejs", "Vue.js"),
    (r"angular", "Angular"),
    (r"next\.js|nextjs|_next/", "Next.js"),
    (r"laravel", "Laravel"),
    (r"django", "Django"),
    (r"flask", "Flask"),
    (r"express", "Express"),
    (r"bootstrap", "Bootstrap"),
    (r"jquery", "jQuery"),
]


class Fingerprint(BaseModule):
    name = "fingerprint"
    description = "Fingerprinting de tecnologias web (headers, HTML, cookies)"

    async def run(self, target: Target) -> Target:
        techs: dict[str, str] = dict(target.technologies)

        for scheme in ("https", "http"):
            url = f"{scheme}://{target.domain}"
            try:
                async with httpx.AsyncClient(
                    timeout=10, follow_redirects=True, verify=False
                ) as client:
                    resp = await client.get(url)

                for hdr, label in HEADER_TECH.items():
                    val = resp.headers.get(hdr)
                    if val:
                        techs[label] = val

                body = resp.text
                for pattern, name in HTML_PATTERNS:
                    if re.search(pattern, body, re.IGNORECASE):
                        techs[name] = "detected"

                break  # success, skip other scheme
            except Exception:
                continue

        target.technologies = techs
        return target
