from __future__ import annotations

import asyncio
import re
import socket

import httpx

from core.module import BaseModule
from core.target import Target

DNS_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]


class OSINT(BaseModule):
    name = "osint"
    description = "Coleta OSINT: DNS, WHOIS e e-mails expostos"

    async def run(self, target: Target) -> Target:
        await asyncio.gather(
            self._resolve_dns(target),
            self._whois(target),
            self._harvest_emails(target),
        )
        return target

    async def _resolve_dns(self, target: Target) -> None:
        records: dict[str, list[str]] = {}
        try:
            import aiodns

            resolver = aiodns.DNSResolver()
            for rtype in DNS_TYPES:
                try:
                    result = await resolver.query(target.domain, rtype)
                    if isinstance(result, list):
                        records[rtype] = [str(r) for r in result]
                    else:
                        records[rtype] = [str(result)]
                except Exception:
                    pass
        except ImportError:
            # Fallback: basic A record
            try:
                ip = socket.gethostbyname(target.domain)
                records["A"] = [ip]
                if not target.ip:
                    target.ip = ip
            except Exception:
                pass

        if records.get("A") and not target.ip:
            target.ip = records["A"][0]
        target.dns_records = records

    async def _whois(self, target: Target) -> None:
        try:
            import whois

            w = await asyncio.get_event_loop().run_in_executor(
                None, whois.whois, target.domain
            )
            target.whois_data = {
                "registrar": str(w.registrar or ""),
                "creation_date": str(w.creation_date or ""),
                "expiration_date": str(w.expiration_date or ""),
                "name_servers": str(w.name_servers or ""),
                "org": str(w.org or ""),
            }
        except Exception:
            pass

    async def _harvest_emails(self, target: Target) -> None:
        emails: set[str] = set(target.emails)
        try:
            async with httpx.AsyncClient(timeout=10, follow_redirects=True, verify=False) as client:
                for path in ("", "/contact", "/about"):
                    try:
                        resp = await client.get(f"https://{target.domain}{path}")
                        found = re.findall(
                            r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
                            resp.text,
                        )
                        emails.update(found)
                    except Exception:
                        pass
        except Exception:
            pass
        target.emails = sorted(emails)
