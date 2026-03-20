from __future__ import annotations

import time

from rich.console import Console
from rich.panel import Panel

from .module import BaseModule
from .target import Target

console = Console()


class Pipeline:
    def __init__(self, modules: list[BaseModule] | None = None):
        self.modules: list[BaseModule] = modules or []

    def add(self, module: BaseModule) -> None:
        self.modules.append(module)

    async def run(self, target: Target, selected: list[str] | None = None) -> Target:
        total_start = time.time()
        for mod in self.modules:
            if selected and mod.name not in selected:
                continue
            if not mod.enabled(target):
                console.print(f"[dim]Pulando {mod.name} (não habilitado)[/dim]")
                continue
            console.print(Panel(f"[bold cyan]Executando: {mod.name}[/bold cyan]"))
            mod_start = time.time()
            try:
                target = await mod.run(target)
            except Exception as exc:
                console.print(f"[bold red]Módulo {mod.name} falhou: {exc}[/bold red]")
            elapsed = time.time() - mod_start
            console.print(f"[dim]  ⏱ {mod.name} concluído em {elapsed:.2f}s[/dim]")
        total_elapsed = time.time() - total_start
        console.print(f"\n[bold green]Pipeline concluída em {total_elapsed:.2f}s[/bold green]")
        return target
