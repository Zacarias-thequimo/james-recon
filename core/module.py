from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .target import Target


class BaseModule(ABC):
    name: str = "base"
    description: str = ""

    @abstractmethod
    async def run(self, target: Target) -> Target:
        ...

    def enabled(self, target: Target) -> bool:
        return True
