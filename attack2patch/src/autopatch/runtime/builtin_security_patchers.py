from __future__ import annotations

import ast
import difflib
import hashlib
import shlex
from collections.abc import Callable
from pathlib import Path

from autopatch.runtime.fs import ensure_within, sha256_file
from autopatch.runtime.patch_apply import apply_edits_to_text
from autopatch.types import AnalysisResult, Finding, PatchCandidate, PatchFeedback, TextEdit


def _call_name(node: ast.AST) -> str:
    try:
        return ast.unparse(node)
    except (TypeError, ValueError):
        return ""


def _unique_call(
    tree: ast.AST,
    line: int,
    predicate: Callable[[ast.Call], bool],
) -> ast.Call | None:
    matches = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and node.lineno == line and predicate(node)
    ]
    return matches[0] if len(matches) == 1 else None


def _parent_statement(tree: ast.AST, node: ast.AST) -> ast.stmt | None:
    parents: dict[ast.AST, ast.AST] = {}
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            parents[child] = parent
    current = node
    while current in parents:
        current = parents[current]
        if isinstance(current, ast.stmt):
            return current
    return None


def _render_statement(source: str, statement: ast.stmt) -> str:
    lines = source.splitlines()
    original = lines[statement.lineno - 1]
    indent = original[: len(original) - len(original.lstrip())]
    rendered = ast.unparse(ast.fix_missing_locations(statement))
    return "\n".join(indent + line if line else line for line in rendered.splitlines())


def _candidate(
    *,
    target: Path,
    finding: Finding,
    analysis: AnalysisResult,
    source: str,
    statement: ast.stmt,
    replacement: str,
    provider: str,
    title: str,
    description: str,
    effect: str,
    metadata: dict[str, object],
) -> PatchCandidate:
    path = ensure_within(target, target / finding.file)
    edit = TextEdit(
        file=finding.file,
        start_line=statement.lineno,
        end_line=getattr(statement, "end_lineno", statement.lineno),
        replacement=replacement,
        original_sha256=sha256_file(path),
    )
    patched = apply_edits_to_text(source, [edit])
    diff = "".join(
        difflib.unified_diff(
            source.splitlines(keepends=True),
            patched.splitlines(keepends=True),
            fromfile=f"a/{finding.file}",
            tofile=f"b/{finding.file}",
        )
    )
    candidate_hash = hashlib.sha256(
        f"{finding.finding_id}\n{diff}".encode()
    ).hexdigest()
    return PatchCandidate(
        candidate_id=f"PATCH-{candidate_hash[:12].upper()}",
        finding_id=finding.finding_id,
        title=title,
        description=description,
        rationale=analysis.recommended_fix,
        expected_security_effect=effect,
        edits=[edit],
        unified_diff=diff,
        changed_files=[finding.file],
        changed_lines=(
            edit.end_line
            - edit.start_line
            + 1
            + max(1, len(edit.replacement.splitlines()))
        ),
        provider=provider,
        metadata=metadata,
    )


def _load(target: Path, finding: Finding) -> tuple[Path, str, ast.Module]:
    target = target.resolve()
    path = ensure_within(target, target / finding.file)
    source = path.read_text(encoding="utf-8")
    return target, source, ast.parse(source, filename=finding.file)


def _fstring_argv(node: ast.JoinedStr) -> tuple[list[ast.expr], list[str]] | None:
    markers: list[str] = []
    expressions: list[ast.expr] = []
    template: list[str] = []
    for item in node.values:
        if isinstance(item, ast.Constant) and isinstance(item.value, str):
            template.append(item.value)
            continue
        if not isinstance(item, ast.FormattedValue):
            return None
        if item.conversion != -1 or item.format_spec is not None:
            return None
        marker = f"__ATTACK2PATCH_ARG_{len(markers)}__"
        markers.append(marker)
        expressions.append(item.value)
        template.append(marker)
    try:
        tokens = shlex.split("".join(template), posix=True)
    except ValueError:
        return None
    if not tokens or tokens[0] in markers or tokens[0].startswith("-"):
        return None
    unsafe_literal_characters = set(";&|<>`$*?[]{}~\n\r")
    argv: list[ast.expr] = []
    seen: list[str] = []
    for token in tokens:
        if token in markers:
            index = markers.index(token)
            argv.append(expressions[index])
            seen.append(token)
            continue
        if any(marker in token for marker in markers):
            return None
        if any(character in unsafe_literal_characters for character in token):
            return None
        argv.append(ast.Constant(value=token))
    if seen != markers:
        return None
    return argv, [ast.unparse(expression) for expression in expressions]


class BuiltinCwe78Patcher:
    """Convert a narrow shell=True f-string command into a fixed argv invocation."""

    name = "builtin-cwe78-argv"

    def generate(
        self,
        target: Path,
        finding: Finding,
        analysis: AnalysisResult,
        feedback: list[PatchFeedback] | None = None,
    ) -> list[PatchCandidate]:
        if finding.cwe != "CWE-78" or finding.sink not in {
            "subprocess.run",
            "subprocess.call",
            "subprocess.Popen",
        }:
            return []
        target, source, tree = _load(target, finding)
        call = _unique_call(
            tree,
            finding.line,
            lambda item: _call_name(item.func) == finding.sink,
        )
        if call is None or not call.args or not isinstance(call.args[0], ast.JoinedStr):
            return []
        shell_keywords = [keyword for keyword in call.keywords if keyword.arg == "shell"]
        if len(shell_keywords) != 1 or not (
            isinstance(shell_keywords[0].value, ast.Constant)
            and shell_keywords[0].value.value is True
        ):
            return []
        converted = _fstring_argv(call.args[0])
        if converted is None:
            return []
        argv, dynamic_arguments = converted
        statement = _parent_statement(tree, call)
        if statement is None:
            return []
        call.args[0] = ast.List(elts=argv, ctx=ast.Load())
        call.keywords = [keyword for keyword in call.keywords if keyword.arg != "shell"]
        replacement = _render_statement(source, statement)
        return [
            _candidate(
                target=target,
                finding=finding,
                analysis=analysis,
                source=source,
                statement=statement,
                replacement=replacement,
                provider=self.name,
                title="Execute a fixed argv list without a shell",
                description=(
                    "Replace the shell f-string with a fixed executable/option list and keep "
                    "attacker-controlled values as standalone argv elements."
                ),
                effect="Shell metacharacters in dynamic values are no longer interpreted.",
                metadata={
                    "oracle": "python-ast-subprocess-argv",
                    "call_line": statement.lineno,
                    "dynamic_arguments": dynamic_arguments,
                },
            )
        ]


class BuiltinCwe502YamlPatcher:
    """Replace explicit unsafe PyYAML object construction with safe_load."""

    name = "builtin-cwe502-yaml-safe-load"
    _UNSAFE_LOADERS = {
        "Loader",
        "FullLoader",
        "UnsafeLoader",
        "yaml.Loader",
        "yaml.FullLoader",
        "yaml.UnsafeLoader",
    }

    @classmethod
    def _unsafe_yaml_call(cls, call: ast.Call) -> bool:
        name = _call_name(call.func)
        if name == "yaml.unsafe_load":
            return len(call.args) == 1 and not call.keywords
        if name != "yaml.load" or len(call.args) != 1:
            return False
        if not call.keywords:
            return True
        return len(call.keywords) == 1 and call.keywords[0].arg == "Loader" and (
            _call_name(call.keywords[0].value) in cls._UNSAFE_LOADERS
        )

    def generate(
        self,
        target: Path,
        finding: Finding,
        analysis: AnalysisResult,
        feedback: list[PatchFeedback] | None = None,
    ) -> list[PatchCandidate]:
        if finding.cwe != "CWE-502" or finding.sink not in {
            "yaml.load",
            "yaml.unsafe_load",
        }:
            return []
        target, source, tree = _load(target, finding)
        call = _unique_call(tree, finding.line, self._unsafe_yaml_call)
        if call is None:
            return []
        statement = _parent_statement(tree, call)
        if statement is None:
            return []
        call.func = ast.Attribute(
            value=ast.Name(id="yaml", ctx=ast.Load()),
            attr="safe_load",
            ctx=ast.Load(),
        )
        call.keywords = []
        replacement = _render_statement(source, statement)
        return [
            _candidate(
                target=target,
                finding=finding,
                analysis=analysis,
                source=source,
                statement=statement,
                replacement=replacement,
                provider=self.name,
                title="Use PyYAML safe_load",
                description="Disable arbitrary Python object construction for YAML input.",
                effect="Untrusted YAML can only construct safe scalar and collection types.",
                metadata={
                    "oracle": "python-ast-yaml-safe-load",
                    "call_line": statement.lineno,
                },
            )
        ]


class BuiltinCwe22FlaskPatcher:
    """Use Flask's directory-aware send API for a narrow path-join pattern."""

    name = "builtin-cwe22-flask-safe-directory"

    @staticmethod
    def _vulnerable_call(call: ast.Call) -> bool:
        if _call_name(call.func) != "flask.send_file" or len(call.args) != 1:
            return False
        joined = call.args[0]
        return (
            isinstance(joined, ast.Call)
            and _call_name(joined.func) == "os.path.join"
            and len(joined.args) == 2
            and not joined.keywords
            and not isinstance(joined.args[1], ast.Constant)
        )

    def generate(
        self,
        target: Path,
        finding: Finding,
        analysis: AnalysisResult,
        feedback: list[PatchFeedback] | None = None,
    ) -> list[PatchCandidate]:
        if (
            finding.cwe != "CWE-22"
            or finding.sink != "flask.send_file"
            or finding.metadata.get("root_trusted") is not True
        ):
            return []
        target, source, tree = _load(target, finding)
        call = _unique_call(tree, finding.line, self._vulnerable_call)
        if call is None:
            return []
        joined = call.args[0]
        assert isinstance(joined, ast.Call)
        if not isinstance(joined.args[0], (ast.Constant, ast.Name, ast.Attribute)):
            return []
        root_expression = ast.unparse(joined.args[0])
        path_expression = ast.unparse(joined.args[1])
        statement = _parent_statement(tree, call)
        if statement is None:
            return []
        call.func = ast.Attribute(
            value=ast.Name(id="flask", ctx=ast.Load()),
            attr="send_from_directory",
            ctx=ast.Load(),
        )
        call.args = [joined.args[0], joined.args[1]]
        replacement = _render_statement(source, statement)
        return [
            _candidate(
                target=target,
                finding=finding,
                analysis=analysis,
                source=source,
                statement=statement,
                replacement=replacement,
                provider=self.name,
                title="Send files from a confined Flask directory",
                description=(
                    "Replace send_file(os.path.join(root, user_path)) with Flask's "
                    "safe_join-backed send_from_directory API."
                ),
                effect="Traversal segments are checked against the trusted directory root.",
                metadata={
                    "oracle": "python-ast-flask-safe-directory",
                    "call_line": statement.lineno,
                    "root_expression": root_expression,
                    "path_expression": path_expression,
                },
            )
        ]
