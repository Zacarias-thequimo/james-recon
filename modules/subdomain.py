from __future__ import annotations

import asyncio
from pathlib import Path

import httpx

from core.module import BaseModule
from core.target import Target
from core.paths import wordlist

WORDLIST = wordlist("subdomains.txt")


class SubdomainEnum(BaseModule):
    name = "subdomain"
    description = "Enumeração de subdomínios via wordlist e DNS"

    def __init__(self, wordlist: str | None = None, concurrency: int = 50):
        self.wordlist = Path(wordlist) if wordlist else WORDLIST
        self.concurrency = concurrency

    async def run(self, target: Target) -> Target:
        found: set[str] = set(target.subdomains)

        # crt.sh
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.get(
                    f"https://crt.sh/?q=%.{target.domain}&output=json"
                )
                if resp.status_code == 200:
                    for entry in resp.json():
                        name = entry.get("name_value", "")
                        for sub in name.split("\n"):
                            sub = sub.strip().lower()
                            if sub.endswith(target.domain) and "*" not in sub:
                                found.add(sub)
        except Exception:
            pass

        # Brute force
        if self.wordlist.exists():
            prefixes = [
                line.strip()
                for line in self.wordlist.read_text().splitlines()
                if line.strip()
            ]
            sem = asyncio.Semaphore(self.concurrency)

            async def check(prefix: str) -> str | None:
                fqdn = f"{prefix}.{target.domain}"
                async with sem:
                    try:
                        await asyncio.get_event_loop().getaddrinfo(fqdn, None)
                        return fqdn
                    except Exception:
                        return None

            results = await asyncio.gather(*(check(p) for p in prefixes))
            for r in results:
                if r:
                    found.add(r)

        target.subdomains = sorted(found)
        return target
