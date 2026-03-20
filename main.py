#!/usr/bin/env python3
from __future__ import annotations

import asyncio
import sys
import time

import click
from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich.table import Table
from rich.panel import Panel

from core.pipeline import Pipeline
from core.target import Target
from core.report import generate_json, generate_markdown

from modules.subdomain import SubdomainEnum
from modules.portscan import PortScan
from modules.fingerprint import Fingerprint
from modules.osint import OSINT
from modules.cve_check import CVECheck
from modules.fuzzer import Fuzzer
from modules.ssl_check import SSLCheck
from modules.headers_check import HeadersCheck
from modules.crawler import Crawler
from modules.form_analyzer import FormAnalyzer
from modules.exploit_chain import ExploitChain
from modules.exploit_runner import ExploitRunner
from modules.pg_exploit import PgExploit

console = Console()

VERSION = "1.2.0"

ALL_MODULES_INSTANCES = [
    SubdomainEnum(),
    PortScan(),
    Fingerprint(),
    OSINT(),
    CVECheck(),
    Fuzzer(),
    SSLCheck(),
    HeadersCheck(),
    Crawler(),
    FormAnalyzer(),
    ExploitChain(),
    ExploitRunner(),
    PgExploit(),
]

ALL_MODULES = [m.name for m in ALL_MODULES_INSTANCES]


def build_pipeline(
    ports: str = "",
    threads: int = 50,
    wordlist: str | None = None,
    run_exploits: bool = False,
) -> Pipeline:
    pipeline = Pipeline()
    pipeline.add(SubdomainEnum(wordlist=wordlist, concurrency=threads))
    pipeline.add(PortScan(ports=ports, concurrency=threads))
    pipeline.add(Fingerprint())
    pipeline.add(OSINT())
    pipeline.add(CVECheck())
    pipeline.add(Fuzzer(wordlist=wordlist, concurrency=threads))
    pipeline.add(SSLCheck())
    pipeline.add(HeadersCheck())
    pipeline.add(Crawler(max_pages=50, concurrency=threads))
    pipeline.add(FormAnalyzer())
    pipeline.add(ExploitChain())
    if run_exploits:
        pipeline.add(ExploitRunner())
        pipeline.add(PgExploit())
    return pipeline


def print_summary(target: Target) -> None:
    console.print()
    console.rule("[bold green]Varredura Completa[/bold green]")
    console.print(f"[bold]Alvo:[/bold] {target.domain} ({target.ip})")

    if target.subdomains:
        console.print(f"[bold]Subdomínios:[/bold] {len(target.subdomains)}")

    if target.open_ports:
        table = Table(title="Portas Abertas")
        table.add_column("Porta")
        table.add_column("Serviço")
        table.add_column("Versão")
        for p in target.open_ports:
            table.add_row(str(p.port), p.service, p.version[:60])
        console.print(table)

    if target.technologies:
        console.print("[bold]Tecnologias:[/bold]")
        for k, v in target.technologies.items():
            console.print(f"  {k}: {v}")

    if target.cves:
        console.print(f"\n[bold red]CVEs encontradas:[/bold red] {len(target.cves)}")
        for cve in target.cves[:10]:
            console.print(f"  {cve['id']} — {cve.get('summary', '')[:80]}")

    if target.fuzz_results:
        console.print(f"\n[bold]Resultados do fuzzing:[/bold] {len(target.fuzz_results)}")
        for f in target.fuzz_results[:15]:
            console.print(f"  [{f.status}] {f.url}")

    if target.ssl_info:
        console.print(f"\n[bold]SSL/TLS:[/bold] {len(target.ssl_info)} hosts analisados")
        for host, info in list(target.ssl_info.items())[:3]:
            days = info.get("days_until_expiry", "?")
            console.print(f"  {host}: {info.get('protocol', '?')} | {info.get('issuer', '?')} | expira em {days}d")

    if target.security_headers:
        missing = target.security_headers.get("missing", [])
        if missing:
            console.print(f"\n[bold yellow]Security Headers ausentes:[/bold yellow] {', '.join(missing)}")
        leaks = target.security_headers.get("info_leak", {})
        if leaks:
            console.print(f"[dim]Info leak: {', '.join(f'{k}={v}' for k,v in leaks.items())}[/dim]")

    if target.cors_issues:
        console.print(f"\n[bold red]CORS Issues:[/bold red] {len(target.cors_issues)}")
        for ci in target.cors_issues:
            console.print(f"  {ci['host']}: ACAO={ci['acao']} [{ci['severity']}]")

    if target.forms:
        console.print(f"\n[bold]Formulários:[/bold] {len(target.forms)}")
        for f in target.forms[:5]:
            csrf = "[green]CSRF[/green]" if f.get("has_csrf") else "[red]sem CSRF[/red]"
            inputs = ", ".join(i["name"] for i in f.get("inputs", [])[:4])
            console.print(f"  {f['method']} {f.get('action', f.get('page', '?'))} ({csrf}) [{inputs}]")

    if target.sqli_results:
        console.print(f"\n[bold red]SQLi Detectado:[/bold red] {len(target.sqli_results)}")
        for sr in target.sqli_results:
            console.print(f"  [{sr['severity']}] {sr['method']} {sr['url']} param={sr['param']} ({sr['type']})")

    if target.vulns:
        console.print(f"\n[bold red]Vulnerabilidades:[/bold red] {len(target.vulns)}")
        for v in target.vulns:
            sev = v.get("severity", "?")
            color = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "dim"}.get(sev, "white")
            console.print(f"  [{color}][{sev}][/{color}] {v.get('type', '')} — {v.get('detail', '')[:100]}")

    if target.exploit_suggestions:
        console.print(f"\n[bold yellow]Sugestões de exploit:[/bold yellow] {len(target.exploit_suggestions)}")
        for ex in target.exploit_suggestions:
            console.print(f"  • {ex['name']} ({ex['type']})")

    if target.exploit_results:
        console.print(f"\n[bold red]Resultados de Exploração:[/bold red] {len(target.exploit_results)}")
        for er in target.exploit_results:
            sev = er.get("severity", "?")
            color = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "dim"}.get(sev, "white")
            console.print(f"  [{color}][{sev}][/{color}] {er.get('service', '')} — {er.get('detail', '')}")


def ask_save(target: Target) -> None:
    """Pergunta ao usuário se deseja salvar o relatório."""
    console.print()
    if Confirm.ask("[bold]Salvar relatório?[/bold]", default=True):
        fmt = Prompt.ask("Formato", choices=["json", "md"], default="json")
        default_name = f"james_relatorio_{target.domain}.{fmt}"
        path = Prompt.ask("Nome do arquivo", default=default_name)
        if fmt == "json":
            generate_json(target, path)
        else:
            generate_markdown(target, path)
        console.print(f"[green]Salvo em {path}[/green]")
    else:
        console.print("[dim]Relatório não salvo.[/dim]")


# ── CLI ──────────────────────────────────────────────────────────────────────

CLI_EPILOG = """
Exemplos:
  james scan -t exemplo.com
  james scan -t exemplo.com -m subdomain,portscan
  james scan -t exemplo.com -p 1-1000 -o relatorio.json
  james scan -t exemplo.com --i-have-permission
  james                          (modo interativo)
"""

SCAN_EPILOG = """
Exemplos:
  james scan -t exemplo.com
  james scan -t exemplo.com -m subdomain,portscan -o resultado.json
  james scan -t exemplo.com -p 80,443,8080 --threads 100
  james scan -t exemplo.com -w /usr/share/wordlists/dirb/common.txt
  james scan -t exemplo.com --i-have-permission --format md -o report.md
"""


@click.group(invoke_without_command=True, epilog=CLI_EPILOG)
@click.version_option(VERSION, prog_name="James")
@click.pass_context
def cli(ctx):
    """James — Toolkit de reconhecimento e exploração para pentest e CTF."""
    if ctx.invoked_subcommand is None:
        interactive()


@cli.command(epilog=SCAN_EPILOG)
@click.option("--target", "-t", required=True, help="Domínio alvo")
@click.option("--modules", "-m", default="", help="Módulos separados por vírgula")
@click.option("--output", "-o", default="", help="Caminho do arquivo de saída")
@click.option("--format", "fmt", type=click.Choice(["json", "md"]), default="json", help="Formato de saída")
@click.option("--ports", "-p", default="", help="Faixa de portas (ex: 1-1000 ou 80,443)")
@click.option("--threads", default=50, help="Nível de concorrência")
@click.option("--wordlist", "-w", default=None, help="Caminho para wordlist customizada")
@click.option("--i-have-permission", is_flag=True, default=False, help="Habilitar exploração ativa")
def scan(target: str, modules: str, output: str, fmt: str, ports: str, threads: int, wordlist: str | None, i_have_permission: bool):
    """Executar pipeline de reconhecimento contra um alvo."""
    if i_have_permission:
        console.print("[bold red]⚠ MODO EXPLOIT ATIVADO — certifique-se de ter autorização por escrito[/bold red]")
    console.print(f"[bold]James v{VERSION}[/bold] varrendo [cyan]{target}[/cyan]")

    t = Target(domain=target)
    pipeline = build_pipeline(ports=ports, threads=threads, wordlist=wordlist, run_exploits=i_have_permission)
    selected = [m.strip() for m in modules.split(",") if m.strip()] if modules else None
    start = time.time()
    t = asyncio.run(pipeline.run(t, selected=selected))
    elapsed = time.time() - start
    print_summary(t)
    console.print(f"\n[bold]Tempo total: {elapsed:.2f}s[/bold]")

    if output:
        if fmt == "json":
            generate_json(t, output)
        else:
            generate_markdown(t, output)
        console.print(f"\n[green]Relatório salvo em {output}[/green]")


# ── Modo Interativo ──────────────────────────────────────────────────────────

BANNER = rf"""
     ██╗ █████╗ ███╗   ███╗███████╗███████╗
     ██║██╔══██╗████╗ ████║██╔════╝██╔════╝
     ██║███████║██╔████╔██║█████╗  ███████╗
██   ██║██╔══██║██║╚██╔╝██║██╔══╝  ╚════██║
╚█████╔╝██║  ██║██║ ╚═╝ ██║███████╗███████║
 ╚════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝╚══════╝
    Toolkit de Reconhecimento & Exploração v{VERSION}
"""


def interactive():
    """Modo interativo com menu."""
    console.print(Panel(BANNER, style="bold cyan", expand=False))
    console.print("[dim]Digite 'ajuda' para ver comandos, 'sair' para encerrar.[/dim]\n")

    target: Target | None = None
    exploit_mode = False

    while True:
        try:
            cmd = Prompt.ask("[bold cyan]james[/bold cyan]").strip().lower()
        except (KeyboardInterrupt, EOFError):
            console.print("\n[dim]Até mais.[/dim]")
            break

        if not cmd:
            continue

        parts = cmd.split(None, 1)
        command = parts[0]
        args = parts[1] if len(parts) > 1 else ""

        if command in ("sair", "quit", "exit", "q"):
            if target:
                ask_save(target)
            console.print("[dim]Até mais.[/dim]")
            break

        elif command in ("ajuda", "help"):
            _print_help()

        elif command in ("alvo", "target", "set"):
            domain = args or Prompt.ask("Domínio alvo")
            target = Target(domain=domain.strip())
            console.print(f"[green]Alvo definido: {target.domain}[/green]")

        elif command in ("modo-exploit", "exploit-mode"):
            exploit_mode = not exploit_mode
            state = "[bold red]LIGADO[/bold red]" if exploit_mode else "[dim]DESLIGADO[/dim]"
            console.print(f"Modo exploit: {state}")

        elif command in ("varrer", "scan"):
            if not target:
                console.print("[red]Defina um alvo primeiro: alvo <domínio>[/red]")
                continue
            console.print(f"[bold]Varrendo {target.domain}...[/bold]")
            pipeline = build_pipeline(run_exploits=exploit_mode)
            start = time.time()
            target = asyncio.run(pipeline.run(target))
            elapsed = time.time() - start
            print_summary(target)
            console.print(f"\n[bold]Tempo total: {elapsed:.2f}s[/bold]")
            ask_save(target)

        elif command in ("rodar", "run"):
            if not target:
                console.print("[red]Defina um alvo primeiro: alvo <domínio>[/red]")
                continue
            mod_names = [m.strip() for m in args.split(",") if m.strip()] if args else None
            if not mod_names:
                console.print(f"[dim]Módulos disponíveis: {', '.join(ALL_MODULES)}[/dim]")
                mod_input = Prompt.ask("Módulos para rodar (separados por vírgula)")
                mod_names = [m.strip() for m in mod_input.split(",") if m.strip()]
            pipeline = build_pipeline(run_exploits=exploit_mode)
            start = time.time()
            target = asyncio.run(pipeline.run(target, selected=mod_names))
            elapsed = time.time() - start
            print_summary(target)
            console.print(f"\n[bold]Tempo total: {elapsed:.2f}s[/bold]")
            ask_save(target)

        elif command in ("status", "estado"):
            if not target:
                console.print("[dim]Nenhum alvo definido.[/dim]")
            else:
                print_summary(target)

        elif command in ("salvar", "save"):
            if not target:
                console.print("[red]Nada para salvar. Execute uma varredura primeiro.[/red]")
                continue
            ask_save(target)

        elif command in ("modulos", "modules"):
            table = Table(title="Módulos Disponíveis", show_header=True, header_style="bold cyan")
            table.add_column("Nome", style="bold")
            table.add_column("Tipo")
            table.add_column("Descrição")
            for mod in ALL_MODULES_INSTANCES:
                tipo = "[red]exploit[/red]" if mod.name in ("exploit_runner", "pg_exploit") else "recon"
                table.add_row(mod.name, tipo, mod.description)
            console.print(table)

        elif command in ("limpar", "reset"):
            target = None
            exploit_mode = False
            console.print("[dim]Sessão reiniciada.[/dim]")

        else:
            console.print(f"[red]Comando desconhecido: {command}. Digite 'ajuda'.[/red]")


def _print_help():
    help_table = Table(title="Comandos do James", show_header=True, header_style="bold cyan")
    help_table.add_column("Comando", style="bold")
    help_table.add_column("Descrição")
    help_table.add_column("Exemplo", style="dim")
    help_table.add_row("alvo <domínio>", "Definir o domínio alvo", "alvo exemplo.com")
    help_table.add_row("varrer", "Executar pipeline completo no alvo", "varrer")
    help_table.add_row("rodar <mod1,mod2,...>", "Executar módulos específicos", "rodar subdomain,portscan")
    help_table.add_row("modulos", "Listar módulos disponíveis", "modulos")
    help_table.add_row("modo-exploit", "Alternar modo exploit LIGADO/DESLIGADO", "modo-exploit")
    help_table.add_row("status", "Mostrar resultados atuais", "status")
    help_table.add_row("salvar", "Salvar relatório (JSON/MD)", "salvar")
    help_table.add_row("limpar", "Limpar alvo e resultados", "limpar")
    help_table.add_row("ajuda", "Mostrar esta ajuda", "ajuda")
    help_table.add_row("sair", "Salvar (opcional) e encerrar", "sair")
    console.print(help_table)
    console.print()
    console.print("[bold]Dicas:[/bold]")
    console.print("  • Use [cyan]rodar subdomain,portscan[/cyan] para executar só módulos específicos")
    console.print("  • Ative [cyan]modo-exploit[/cyan] apenas com autorização por escrito")
    console.print("  • Relatórios podem ser exportados em JSON ou Markdown")
    console.print()


if __name__ == "__main__":
    cli()
