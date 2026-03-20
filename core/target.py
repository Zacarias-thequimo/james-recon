from __future__ import annotations

import json
from dataclasses import dataclass, field


@dataclass
class PortInfo:
    port: int
    state: str = "open"
    service: str = ""
    version: str = ""

    def to_dict(self) -> dict:
        return {"port": self.port, "state": self.state, "service": self.service, "version": self.version}


@dataclass
class FuzzResult:
    url: str
    status: int
    length: int

    def to_dict(self) -> dict:
        return {"url": self.url, "status": self.status, "length": self.length}


@dataclass
class Target:
    domain: str
    ip: str = ""
    subdomains: list[str] = field(default_factory=list)
    open_ports: list[PortInfo] = field(default_factory=list)
    technologies: dict[str, str] = field(default_factory=dict)
    emails: list[str] = field(default_factory=list)
    dns_records: dict[str, list[str]] = field(default_factory=dict)
    whois_data: dict = field(default_factory=dict)
    cves: list[dict] = field(default_factory=list)
    fuzz_results: list[FuzzResult] = field(default_factory=list)
    exploit_suggestions: list[dict] = field(default_factory=list)
    exploit_results: list[dict] = field(default_factory=list)
    # Deep recon fields
    ssl_info: dict = field(default_factory=dict)
    security_headers: dict = field(default_factory=dict)
    cors_issues: list[dict] = field(default_factory=list)
    forms: list[dict] = field(default_factory=list)
    sqli_results: list[dict] = field(default_factory=list)
    vulns: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "domain": self.domain,
            "ip": self.ip,
            "subdomains": self.subdomains,
            "open_ports": [p.to_dict() for p in self.open_ports],
            "technologies": self.technologies,
            "emails": self.emails,
            "dns_records": self.dns_records,
            "whois_data": self.whois_data,
            "cves": self.cves,
            "fuzz_results": [f.to_dict() for f in self.fuzz_results],
            "exploit_suggestions": self.exploit_suggestions,
            "exploit_results": self.exploit_results,
            "ssl_info": self.ssl_info,
            "security_headers": self.security_headers,
            "cors_issues": self.cors_issues,
            "forms": self.forms,
            "sqli_results": self.sqli_results,
            "vulns": self.vulns,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str)
