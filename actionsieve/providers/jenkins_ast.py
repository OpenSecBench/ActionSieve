"""Tree-sitter based Groovy AST parser for Jenkins pipelines."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import tree_sitter_groovy as tsgroovy
from tree_sitter import Language, Parser

if TYPE_CHECKING:
    from tree_sitter import Node, Tree

_LANGUAGE = Language(tsgroovy.language())

SHELL_COMMANDS = frozenset({"sh", "bat", "powershell"})


@dataclass
class ShellCall:
    command: str
    cmd_type: str
    is_safe_string: bool
    line: int


@dataclass
class StageInfo:
    name: str
    node: Node
    line: int


@dataclass
class LibraryRef:
    raw: str
    name: str
    version: str
    line: int


@dataclass
class AgentInfo:
    kind: str
    label: str


@dataclass
class CredentialRef:
    cred_id: str


@dataclass
class PipelineInfo:
    is_declarative: bool
    root: Node
    stages: list[StageInfo] = field(default_factory=list)
    shell_calls: list[ShellCall] = field(default_factory=list)
    libraries: list[LibraryRef] = field(default_factory=list)
    agent: AgentInfo | None = None
    credentials: list[CredentialRef] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)


def parse_groovy(text: str) -> Tree:
    parser = Parser(_LANGUAGE)
    return parser.parse(text.encode("utf-8"))


def extract_pipeline_info(tree: Tree) -> PipelineInfo:
    root = tree.root_node
    pipeline_node = _find_method_call(root, "pipeline")
    node_block = _find_method_call(root, "node")
    is_declarative = pipeline_node is not None

    target = pipeline_node or node_block or root
    info = PipelineInfo(is_declarative=is_declarative, root=target)

    info.libraries = _extract_annotations(root)
    info.agent = _extract_agent(target)
    info.env = _extract_env(target)
    info.credentials = _extract_credentials(target)

    info.stages = _extract_stages(target)
    if not is_declarative and not info.stages:
        info.shell_calls = find_shell_calls(target)

    return info


def find_shell_calls(node: Node) -> list[ShellCall]:
    calls: list[ShellCall] = []
    _walk_shell_calls(node, calls)
    return calls


def _walk_shell_calls(node: Node, calls: list[ShellCall]) -> None:
    name = _get_call_name(node)
    if name in SHELL_COMMANDS:
        call = _parse_shell_call(node, name)
        if call:
            calls.append(call)
        return

    for child in node.children:
        _walk_shell_calls(child, calls)


def _parse_shell_call(node: Node, cmd_type: str) -> ShellCall | None:
    arg_text, is_safe = _extract_call_string_arg(node)
    if arg_text is None:
        return None
    return ShellCall(
        command=arg_text,
        cmd_type=cmd_type,
        is_safe_string=is_safe,
        line=node.start_point[0] + 1,
    )


def _extract_call_string_arg(node: Node) -> tuple[str | None, bool]:
    args = _find_child(node, "argument_list")
    if not args:
        return None, False

    for child in args.children:
        if child.type == "character_literal":
            return _strip_quotes(child), True
        if child.type == "string_literal":
            return _concat_string_literal(child), False
        if child.type == "map_item":
            key_node = _find_child(child, "identifier")
            if key_node and _node_text(key_node) == "script":
                val = _map_item_value(child)
                if val:
                    if val.type == "character_literal":
                        return _strip_quotes(val), True
                    if val.type == "string_literal":
                        return _concat_string_literal(val), False
    return None, False


def _extract_stages(node: Node) -> list[StageInfo]:
    stages: list[StageInfo] = []
    _walk_stages(node, stages)
    return stages


def _walk_stages(node: Node, stages: list[StageInfo]) -> None:
    name = _get_call_name(node)
    if name == "stage":
        stage_name = _first_string_arg(node)
        if stage_name:
            stages.append(
                StageInfo(
                    name=stage_name,
                    node=node,
                    line=node.start_point[0] + 1,
                )
            )
            return

    for child in node.children:
        _walk_stages(child, stages)


def _extract_annotations(root: Node) -> list[LibraryRef]:
    refs: list[LibraryRef] = []
    for child in root.children:
        if child.type == "local_variable_declaration":
            mods = _find_child(child, "modifiers")
            if mods:
                for ann in _children_of_type(mods, "annotation"):
                    ref = _parse_library_annotation(ann)
                    if ref:
                        refs.append(ref)
    return refs


def _parse_library_annotation(ann: Node) -> LibraryRef | None:
    ident = _find_child(ann, "identifier")
    if not ident or _node_text(ident) != "Library":
        return None

    arg_list = _find_child(ann, "annotation_argument_list")
    if not arg_list:
        return None

    for child in arg_list.children:
        if child.type in ("character_literal", "string_literal"):
            is_char = child.type == "character_literal"
            raw = _strip_quotes(child) if is_char else _concat_string_literal(child)
            name, version = _split_lib_ref(raw)
            return LibraryRef(
                raw=raw,
                name=name,
                version=version,
                line=ann.start_point[0] + 1,
            )
    return None


def _split_lib_ref(raw: str) -> tuple[str, str]:
    if "@" in raw:
        name, _, version = raw.partition("@")
        return name, version
    return raw, ""


def _extract_agent(node: Node) -> AgentInfo | None:
    if _get_call_name(node) == "node":
        label = _first_string_arg(node)
        return AgentInfo(kind="label" if label else "any", label=label or "any")

    closure = _find_child(node, "closure")
    if not closure:
        return None

    for child in closure.children:
        if child.type == "local_variable_declaration":
            type_id = _find_child(child, "type_identifier")
            if type_id and _node_text(type_id) == "agent":
                var = _find_child(child, "variable_declarator")
                ident = _find_child(var, "identifier") if var else None
                val = _node_text(ident) if ident else "any"
                return AgentInfo(kind=val if val == "none" else "any", label=val)

        if child.type == "expression_statement":
            call = _unwrap_call(child)
            if call and _get_call_name(call) == "agent":
                return _parse_agent_block(call)
    return None


def _parse_agent_block(node: Node) -> AgentInfo | None:
    closure = _find_child(node, "closure")
    if not closure:
        return None

    for child in closure.children:
        call = _unwrap_call(child)
        if not call:
            continue
        name = _get_call_name(call)
        if name == "docker":
            image = _find_nested_string(call, "image")
            return AgentInfo(kind="docker", label=image or "docker")
        if name == "label":
            return AgentInfo(kind="label", label=_first_string_arg(call) or "")
    return None


def _unwrap_call(node: Node) -> Node | None:
    if node.type in ("method_invocation", "juxt_function_call"):
        return node
    if node.type == "expression_statement":
        return _find_child(node, "method_invocation") or _find_child(node, "juxt_function_call")
    return None


def _find_nested_string(node: Node, target: str) -> str | None:
    if _get_call_name(node) == target:
        return _first_string_arg(node)
    for child in node.children:
        result = _find_nested_string(child, target)
        if result:
            return result
    return None


def _extract_env(node: Node) -> dict[str, str]:
    env: dict[str, str] = {}
    env_call = _find_method_call(node, "environment")
    if not env_call:
        return env

    closure = _find_child(env_call, "closure")
    if not closure:
        return env

    for child in closure.children:
        assign: Node | None = child
        if child.type == "expression_statement":
            assign = _find_child(child, "assignment_expression")
        if assign and assign.type == "assignment_expression":
            lhs = assign.children[0] if assign.children else None
            rhs = assign.children[-1] if len(assign.children) >= 3 else None
            if lhs and rhs:
                key = _node_text(lhs)
                is_char = rhs.type == "character_literal"
                val = _strip_quotes(rhs) if is_char else _node_text(rhs).strip("'\"")
                env[key] = val
    return env


def _extract_credentials(node: Node) -> list[CredentialRef]:
    creds: list[CredentialRef] = []
    _walk_credentials(node, creds)
    return creds


def _walk_credentials(node: Node, creds: list[CredentialRef]) -> None:
    name = _get_call_name(node)
    if name == "withCredentials":
        args = _find_child(node, "argument_list")
        if args:
            for arr in _children_of_type(args, "array_literal"):
                for call in arr.children:
                    if call.type == "method_invocation":
                        cred_id = _find_map_value(call, "credentialsId")
                        if cred_id:
                            creds.append(CredentialRef(cred_id=cred_id))
        return

    for child in node.children:
        _walk_credentials(child, creds)


def _find_map_value(node: Node, key: str) -> str | None:
    args = _find_child(node, "argument_list")
    if not args:
        return None
    for child in args.children:
        if child.type == "map_item":
            key_node = _find_child(child, "identifier")
            if key_node and _node_text(key_node) == key:
                val = _map_item_value(child)
                if val and val.type == "character_literal":
                    return _strip_quotes(val)
    return None


# --- AST navigation helpers ---


def _get_call_name(node: Node) -> str | None:
    if node.type in ("method_invocation", "juxt_function_call"):
        ident = _find_child(node, "identifier")
        if ident:
            return _node_text(ident)
    return None


def _find_child(node: Node, child_type: str) -> Node | None:
    for child in node.children:
        if child.type == child_type:
            return child
    return None


def _children_of_type(node: Node, child_type: str) -> list[Node]:
    return [c for c in node.children if c.type == child_type]


def _find_method_call(node: Node, name: str) -> Node | None:
    if _get_call_name(node) == name:
        return node
    for child in node.children:
        result = _find_method_call(child, name)
        if result:
            return result
    return None


def _first_string_arg(node: Node) -> str | None:
    args = _find_child(node, "argument_list")
    if not args:
        return None
    for child in args.children:
        if child.type == "character_literal":
            return _strip_quotes(child)
        if child.type == "string_literal":
            return _concat_string_literal(child)
    return None


def _map_item_value(item: Node) -> Node | None:
    found_colon = False
    for child in item.children:
        if child.type == ":":
            found_colon = True
        elif found_colon:
            return child
    return None


def _node_text(node: Node) -> str:
    return node.text.decode("utf-8") if node.text else ""


def _strip_quotes(node: Node) -> str:
    text = _node_text(node)
    for q in ("'''", '"""', "'", '"'):
        if text.startswith(q) and text.endswith(q):
            return text[len(q) : -len(q)]
    return text


def _concat_string_literal(node: Node) -> str:
    parts: list[str] = []
    for child in node.children:
        if child.type in ("string_fragment", "multiline_string_fragment", "escape_sequence"):
            parts.append(_node_text(child))
    return "".join(parts)
