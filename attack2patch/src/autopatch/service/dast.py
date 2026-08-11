from __future__ import annotations

from autopatch.providers import DastProvider
from autopatch.types import DastScanResult


class DastService:
    """Run explicitly selected DAST providers without hiding unavailable tooling."""

    def __init__(self, providers: list[DastProvider]) -> None:
        self.providers = {provider.name.removesuffix("-dast"): provider for provider in providers}

    def scan(
        self,
        target: str,
        *,
        tools: list[str] | None = None,
        sandbox_target: bool = False,
    ) -> list[DastScanResult]:
        selected = tools or sorted(self.providers)
        if not selected:
            raise ValueError("no DAST provider is enabled")
        unknown = sorted(set(selected) - self.providers.keys())
        if unknown:
            raise ValueError(f"DAST provider is not enabled: {', '.join(unknown)}")
        results: list[DastScanResult] = []
        for name in selected:
            provider = self.providers[name]
            if not provider.available():
                raise RuntimeError(f"DAST provider is unavailable: {name}")
            results.append(provider.scan(target, sandbox_target=sandbox_target))
        return results
