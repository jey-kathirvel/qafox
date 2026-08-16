"""Deterministic adapter registration without framework branching."""

from __future__ import annotations

from collections.abc import Iterable

from app.smart_data.adapters.base import FrameworkAdapter


class AdapterRegistry:
    def __init__(self, adapters: Iterable[FrameworkAdapter] = ()) -> None:
        self._adapters: dict[str, FrameworkAdapter] = {}
        for adapter in adapters:
            self.register(adapter)

    def register(self, adapter: FrameworkAdapter) -> None:
        name = str(getattr(adapter, "name", "")).strip().lower()
        if not name:
            raise ValueError("Framework adapters require a stable name")
        if name in self._adapters:
            raise ValueError(f"Framework adapter already registered: {name}")
        self._adapters[name] = adapter

    def get(self, name: str) -> FrameworkAdapter | None:
        return self._adapters.get(name.strip().lower())

    def all(self) -> tuple[FrameworkAdapter, ...]:
        return tuple(self._adapters[name] for name in sorted(self._adapters))

    def names(self) -> tuple[str, ...]:
        return tuple(sorted(self._adapters))
