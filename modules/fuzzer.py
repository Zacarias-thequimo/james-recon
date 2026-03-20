from __future__ import annotations

import asyncio
from pathlib import Path

import httpx

from core.module import BaseModule
from core.target import Target, FuzzResult
from core.paths import wordlist

WORDLIST = wordlist("dirs.txt")


class Fuzzer(BaseModule):
    name = "fuzzer"
    description = "Fuzzing de diretórios e arquivos via wordlist"

    def __init__(self, wordlist: str | None = None, concurrency: int = 30, extensions: str = ""):
        self.wordlist = Path(wordlist) if wordlist else WORDLIST
        self.concurrency = concurrency
        self.extensions = [e.strip() for e in extensions.split(",") if e.strip()] if extensions else []

    async def run(self, target: Target) -> Target:
        if not self.wordlist.exists():
            return target

        words = [
            line.strip()
            for line in self.wordlist.read_text().splitlines()
            if line.strip() and not line.startswith("#")
        ]

        paths: list[str] = []
        for w in words:
            paths.append(f"/{w}")
            for ext in self.extensions:
                paths.append(f"/{w}.{ext}")

        base = f"https://{target.domain}"
        sem = asyncio.Semaphore(self.concurrency)
        results: list[FuzzResult] = []

        async def check(client: httpx.AsyncClient, path: str) -> FuzzResult | None:
            url = f"{base}{path}"
            async with sem:
                try:
                    resp = await client.get(url)
                    if resp.status_code < 404:
                        return FuzzResult(url=url, status=resp.status_code, length=len(resp.content))
                except Exception:
                    return None
            return None

        async with httpx.AsyncClient(
            timeout=10, follow_redirects=False, verify=False
        ) as client:
            tasks = [check(client, p) for p in paths]
            for r in await asyncio.gather(*tasks):
                if r:
                    results.append(r)

        target.fuzz_results = sorted(results, key=lambda r: r.status)
        return target
