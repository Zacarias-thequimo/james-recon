from __future__ import annotations

import asyncio
import socket

from core.module import BaseModule
from core.target import Target, PortInfo

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
                993, 995, 1723, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443, 8888, 9090, 27017]

SERVICE_MAP = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios", 143: "imap",
    443: "https", 445: "smb", 993: "imaps", 995: "pop3s", 1723: "pptp",
    3306: "mysql", 3389: "rdp", 5432: "postgresql", 5900: "vnc",
    6379: "redis", 8000: "http-alt", 8080: "http-proxy", 8443: "https-alt",
    8888: "http-alt", 9090: "http-alt", 27017: "mongodb",
}


class PortScan(BaseModule):
    name = "portscan"
    description = "Varredura assíncrona de portas TCP com detecção de serviço"

    def __init__(self, ports: str = "", concurrency: int = 100, timeout: float = 1.5):
        self.ports_spec = ports
        self.concurrency = concurrency
        self.timeout = timeout

    def _parse_ports(self) -> list[int]:
        if not self.ports_spec:
            return COMMON_PORTS
        ports: list[int] = []
        for part in self.ports_spec.split(","):
            if "-" in part:
                lo, hi = part.split("-", 1)
                ports.extend(range(int(lo), int(hi) + 1))
            else:
                ports.append(int(part))
        return ports

    async def run(self, target: Target) -> Target:
        if not target.ip:
            try:
                target.ip = socket.gethostbyname(target.domain)
            except Exception:
                return target

        host = target.ip
        ports = self._parse_ports()
        sem = asyncio.Semaphore(self.concurrency)
        found: list[PortInfo] = []

        async def check(port: int) -> PortInfo | None:
            async with sem:
                try:
                    _, writer = await asyncio.wait_for(
                        asyncio.open_connection(host, port), timeout=self.timeout
                    )
                    writer.close()
                    await writer.wait_closed()
                    return PortInfo(
                        port=port,
                        state="open",
                        service=SERVICE_MAP.get(port, ""),
                    )
                except Exception:
                    return None

        results = await asyncio.gather(*(check(p) for p in ports))
        for r in results:
            if r:
                found.append(r)

        # Try banner grab on open ports
        for pi in found:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, pi.port), timeout=self.timeout
                )
                banner = await asyncio.wait_for(reader.read(1024), timeout=2)
                pi.version = banner.decode(errors="ignore").strip()[:120]
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

        target.open_ports = sorted(found, key=lambda p: p.port)
        return target
