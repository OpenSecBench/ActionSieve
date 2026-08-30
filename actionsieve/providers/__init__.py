"""Platform providers — detection, parsing, and normalization."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from pathlib import Path

    from actionsieve.model import ComponentRef, WorkflowModel


class ParseError(Exception):
    """Raised when a pipeline definition cannot be parsed."""


@dataclass
class ExpressionSyntax:
    delimiters: tuple[str, str]
    env_prefix: str | None = None
    context_roots: list[str] = field(default_factory=list)
    tainted_roots: list[str] = field(default_factory=list)
    safe_indirection: list[str] = field(default_factory=list)


class Provider(Protocol):
    name: str

    def detect(self, repo_path: Path) -> bool: ...
    def find_files(self, repo_path: Path) -> list[Path]: ...
    def parse(self, file_path: Path) -> WorkflowModel: ...
    def resolve_ref(self, ref: ComponentRef) -> ComponentRef: ...
    def expression_syntax(self) -> ExpressionSyntax: ...
    def search_query(self, pattern: dict[str, object]) -> str | None: ...


def _get_providers() -> list[Provider]:
    from actionsieve.providers.github import GitHubProvider

    return [GitHubProvider()]


def auto_detect(repo_path: Path) -> list[Provider]:
    return [p for p in _get_providers() if p.detect(repo_path)]


def get_provider(name: str) -> Provider:
    for p in _get_providers():
        if p.name == name:
            return p
    msg = f"Unknown provider: {name}"
    raise ValueError(msg)
