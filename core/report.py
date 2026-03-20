from __future__ import annotations

from pathlib import Path

from .target import Target


def generate_json(target: Target, path: str) -> None:
    Path(path).write_text(target.to_json())


def generate_markdown(target: Target, path: str) -> None:
    t = target
    lines = [
        f"# Relatório de Reconhecimento: {t.domain}\n",
        f"**IP:** {t.ip}\n",
    ]

    if t.subdomains:
        lines.append("## Subdomínios\n")
        for s in t.subdomains:
            lines.append(f"- {s}")
        lines.append("")

    if t.open_ports:
        lines.append("## Portas Abertas\n")
        lines.append("| Porta | Estado | Serviço | Versão |")
        lines.append("|-------|--------|---------|--------|")
        for p in t.open_ports:
            lines.append(f"| {p.port} | {p.state} | {p.service} | {p.version} |")
        lines.append("")

    if t.technologies:
        lines.append("## Tecnologias\n")
        for k, v in t.technologies.items():
            lines.append(f"- **{k}:** {v}")
        lines.append("")

    if t.dns_records:
        lines.append("## Registros DNS\n")
        for rtype, records in t.dns_records.items():
            lines.append(f"### {rtype}")
            for r in records:
                lines.append(f"- {r}")
        lines.append("")

    if t.whois_data:
        lines.append("## Whois\n")
        for k, v in t.whois_data.items():
            lines.append(f"- **{k}:** {v}")
        lines.append("")

    if t.emails:
        lines.append("## E-mails\n")
        for e in t.emails:
            lines.append(f"- {e}")
        lines.append("")

    if t.cves:
        lines.append("## CVEs\n")
        for cve in t.cves:
            lines.append(f"- **{cve.get('id', '?')}** — {cve.get('summary', '')}")
        lines.append("")

    if t.fuzz_results:
        lines.append("## Resultados de Fuzzing\n")
        lines.append("| URL | Status | Tamanho |")
        lines.append("|-----|--------|---------|")
        for f in t.fuzz_results:
            lines.append(f"| {f.url} | {f.status} | {f.length} |")
        lines.append("")

    if t.exploit_suggestions:
        lines.append("## Sugestões de Exploit\n")
        for ex in t.exploit_suggestions:
            lines.append(f"### {ex.get('name', 'Desconhecido')}")
            lines.append(f"- **Tipo:** {ex.get('type', '')}")
            lines.append(f"- **Descrição:** {ex.get('description', '')}")
            if ex.get("steps"):
                lines.append("- **Passos:**")
                for step in ex["steps"]:
                    lines.append(f"  1. {step}")
        lines.append("")

    if t.exploit_results:
        lines.append("## Resultados de Exploração\n")
        for er in t.exploit_results:
            sev = er.get("severity", "?")
            lines.append(f"- **[{sev}]** {er.get('service', '')} — {er.get('detail', '')}")
        lines.append("")

    if t.ssl_info:
        lines.append("## SSL/TLS\n")
        lines.append("| Host | Protocolo | Cifra | Emissor | Expira | Dias |")
        lines.append("|------|-----------|-------|---------|--------|------|")
        for host, info in t.ssl_info.items():
            lines.append(f"| {host} | {info.get('protocol', '?')} | {info.get('cipher', '?')} | {info.get('issuer', '?')} | {info.get('not_after', '?')} | {info.get('days_until_expiry', '?')} |")
        lines.append("")

    if t.security_headers:
        lines.append("## Security Headers\n")
        present = t.security_headers.get("present", {})
        missing = t.security_headers.get("missing", [])
        if present:
            for label, val in present.items():
                lines.append(f"- **{label}:** {val}")
        if missing:
            lines.append(f"\n**Ausentes:** {', '.join(missing)}")
        leaks = t.security_headers.get("info_leak", {})
        if leaks:
            lines.append(f"\n**Info Leak:** {', '.join(f'{k}={v}' for k, v in leaks.items())}")
        csp_issues = t.security_headers.get("csp_issues", [])
        if csp_issues:
            lines.append(f"\n**CSP Issues:** {'; '.join(csp_issues)}")
        lines.append("")

    if t.cors_issues:
        lines.append("## CORS Issues\n")
        lines.append("| Host | ACAO | ACAC | Severidade |")
        lines.append("|------|------|------|------------|")
        for ci in t.cors_issues:
            lines.append(f"| {ci['host']} | {ci['acao']} | {ci.get('acac', '')} | {ci['severity']} |")
        lines.append("")

    if t.forms:
        lines.append("## Formulários\n")
        lines.append("| Página | Método | Action | Inputs | CSRF |")
        lines.append("|--------|--------|--------|--------|------|")
        for f in t.forms:
            inputs = ", ".join(i["name"] for i in f.get("inputs", []))
            csrf = "Sim" if f.get("has_csrf") else "**Não**"
            lines.append(f"| {f.get('page', '?')} | {f.get('method', '?')} | {f.get('action', '')} | {inputs} | {csrf} |")
        lines.append("")

    if t.sqli_results:
        lines.append("## SQL Injection\n")
        for sr in t.sqli_results:
            lines.append(f"### [{sr['severity']}] {sr['method']} {sr['url']} — param: `{sr['param']}`\n")
            lines.append(f"- **Tipo:** {sr['type']}")
            lines.append(f"- **Detalhe:** {sr['detail']}")
            lines.append(f"- **Baseline:** {sr.get('baseline_size', '?')} bytes")
            lines.append(f"- **SQLi response:** {sr.get('sqli_size', '?')} bytes")
            if sr.get("sleep_confirmed"):
                lines.append("- **SLEEP:** Confirmado")
        lines.append("")

    if t.vulns:
        lines.append("## Vulnerabilidades Consolidadas\n")
        lines.append("| # | Severidade | Tipo | Host | Detalhe |")
        lines.append("|---|-----------|------|------|---------|")
        for i, v in enumerate(t.vulns, 1):
            lines.append(f"| {i} | **{v.get('severity', '?')}** | {v.get('type', '?')} | {v.get('host', '')} | {v.get('detail', '')} |")
        lines.append("")

    Path(path).write_text("\n".join(lines))
