"""GitHub Actions parsing helpers — expressions, refs, and utility functions."""

from __future__ import annotations

import re
from typing import Any

from actionsieve.model import ComponentRef, Expression

EXPRESSION_RE = re.compile(r"\$\{\{\s*(.*?)\s*\}\}")

GITHUB_FIRST_PARTY = frozenset({"actions", "github"})

TAINTED_CONTEXT_PREFIXES = (
    "github.event.pull_request.title",
    "github.event.pull_request.body",
    "github.event.pull_request.head.ref",
    "github.event.pull_request.head.label",
    "github.event.issue.title",
    "github.event.issue.body",
    "github.event.comment.body",
    "github.event.review.body",
    "github.event.review_comment.body",
    "github.event.discussion.title",
    "github.event.discussion.body",
    "github.event.head_commit.message",
    "github.event.head_commit.author.name",
    "github.event.head_commit.author.email",
    "github.event.commits",
    "github.event.workflow_run.display_title",
    "github.event.workflow_run.head_branch",
    "github.event.pages",
    "github.head_ref",
)

GITHUB_OUTPUT_RE = re.compile(r""">>?\s*["']?\$(?:GITHUB_OUTPUT|\{GITHUB_OUTPUT\})["']?""")
OUTPUT_KEY_RE = re.compile(r"""(\w[\w-]*)=""")


def parse_uses(uses: str, lines: list[str]) -> ComponentRef:
    line_num = find_line(lines, uses)

    if "@" in uses:
        path_part, ref = uses.rsplit("@", 1)
    else:
        path_part = uses
        ref = ""

    owner: str | None = None
    name = path_part
    if "/" in path_part:
        parts = path_part.split("/", 1)
        owner = parts[0]
        name = parts[1]

    ref_type = classify_ref(ref)
    is_first_party = owner in GITHUB_FIRST_PARTY if owner else False

    return ComponentRef(
        raw=uses,
        owner=owner,
        name=name,
        ref=ref,
        ref_type=ref_type,
        is_pinned=ref_type == "sha",
        is_first_party=is_first_party,
        line=line_num,
    )


def classify_ref(ref: str) -> str:
    if not ref:
        return "unknown"
    if len(ref) == 40 and all(c in "0123456789abcdef" for c in ref):
        return "sha"
    if re.match(r"^v?\d+(\.\d+)*$", ref):
        return "tag"
    return "branch"


def extract_expressions(
    text: str,
    shell_command: str | None,
    file_lines: list[str] | None = None,
) -> list[Expression]:
    expressions: list[Expression] = []
    for m in EXPRESSION_RE.finditer(text):
        context_path = m.group(1).strip()
        raw = m.group(0)

        in_shell = shell_command is not None and raw in (shell_command or "")
        location = "run" if in_shell else "other"

        is_tainted = any(context_path.startswith(prefix) for prefix in TAINTED_CONTEXT_PREFIXES)

        line = find_line(file_lines or [], raw) if file_lines else 0

        expressions.append(
            Expression(
                raw=raw,
                context_path=context_path,
                location=location,
                is_in_shell=in_shell,
                is_tainted=is_tainted,
                line=line,
            )
        )

    return expressions


def detect_outputs_written(shell_command: str | None) -> list[str]:
    if not shell_command:
        return []
    keys: list[str] = []
    for line in shell_command.splitlines():
        if GITHUB_OUTPUT_RE.search(line):
            key_match = OUTPUT_KEY_RE.search(line)
            if key_match:
                keys.append(key_match.group(1))
    return keys


def find_secrets(data: Any) -> list[str]:
    secrets: list[str] = []
    text = str(data)
    for match in re.finditer(r"\$\{\{\s*secrets\.(\w+)\s*\}\}", text):
        name = match.group(1)
        if name not in secrets:
            secrets.append(name)
    return secrets


def step_text(data: dict[str, Any]) -> str:
    parts: list[str] = []
    for key in ("run", "name", "if"):
        if key in data:
            parts.append(str(data[key]))
    with_data = data.get("with", {})
    if isinstance(with_data, dict):
        for v in with_data.values():
            parts.append(str(v))
    env_data = data.get("env", {})
    if isinstance(env_data, dict):
        for v in env_data.values():
            parts.append(str(v))
    return "\n".join(parts)


def find_line(lines: list[str], needle: str) -> int:
    for i, line in enumerate(lines, 1):
        if needle in line:
            return i
    return 0


def str_dict(raw: Any) -> dict[str, str]:
    if not isinstance(raw, dict):
        return {}
    return {str(k): str(v) for k, v in raw.items()}
