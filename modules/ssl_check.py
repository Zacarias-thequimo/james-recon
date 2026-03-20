from __future__ import annotations

import ssl
import socket
from datetime import datetime, timezone

from core.module import BaseModule
from core.target import Target


class SSLCheck(BaseModule):
    name = "ssl_check"
    description = "Análise de certificado SSL/TLS, protocolo, cifras e validade"

    async def run(self, target: Target) -> Target:
        info: dict = {}
        hosts = [target.domain] + [f"www.{target.domain}"]
        hosts += [s for s in target.subdomains if s not in hosts]

        for host in hosts[:10]:
            cert_info = self._check_host(host)
            if cert_info:
                info[host] = cert_info
                if host == target.domain:
                    # Check expiry
                    not_after = cert_info.get("not_after", "")
                    if not_after:
                        try:
                            exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y GMT")
                            days_left = (exp - datetime.now()).days
                            cert_info["days_until_expiry"] = days_left
                            if days_left < 30:
                                target.vulns.append({
                                    "type": "ssl_expiry",
                                    "severity": "HIGH" if days_left < 7 else "MEDIUM",
                                    "detail": f"Certificado expira em {days_left} dias ({not_after})",
                                    "host": host,
                                })
                        except ValueError:
                            pass
                    # Check hostname mismatch
                    sans = cert_info.get("sans", [])
                    if sans and host not in sans and f"*.{'.'.join(host.split('.')[1:])}" not in sans:
                        target.vulns.append({
                            "type": "ssl_hostname_mismatch",
                            "severity": "MEDIUM",
                            "detail": f"Certificado não cobre {host}. SANs: {sans}",
                            "host": host,
                        })

        target.ssl_info = info
        return target

    def _check_host(self, host: str) -> dict | None:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    protocol = ssock.version()
                    cipher = ssock.cipher()
                    cert = ssock.getpeercert()
                    result = {
                        "protocol": protocol,
                        "cipher": cipher[0] if cipher else "",
                        "bits": cipher[2] if cipher else 0,
                    }
                    if cert:
                        subj = cert.get("subject", ())
                        cn = ""
                        for rdn in subj:
                            for attr, val in rdn:
                                if attr == "commonName":
                                    cn = val
                        issuer_parts = cert.get("issuer", ())
                        issuer = ""
                        for rdn in issuer_parts:
                            for attr, val in rdn:
                                if attr in ("organizationName", "commonName"):
                                    issuer = val
                        sans = [v for _, v in cert.get("subjectAltName", ())]
                        result.update({
                            "cn": cn,
                            "issuer": issuer,
                            "not_before": cert.get("notBefore", ""),
                            "not_after": cert.get("notAfter", ""),
                            "sans": sans,
                        })
                    return result
        except Exception:
            return None
