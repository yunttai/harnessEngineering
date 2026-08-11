from __future__ import annotations

import ast
import difflib
import hashlib
from pathlib import Path

from autopatch.runtime.fs import ensure_within, sha256_file
from autopatch.runtime.patch_apply import apply_edits_to_text
from autopatch.types import AnalysisResult, Finding, PatchCandidate, PatchFeedback, TextEdit


class BuiltinCwe89Patcher:
    """Narrow deterministic patcher for single-file Python f-string SQL queries."""

    name = "builtin-cwe89-parameterizer"

    def generate(
        self,
        target: Path,
        finding: Finding,
        analysis: AnalysisResult,
        feedback: list[PatchFeedback] | None = None,
    ) -> list[PatchCandidate]:
        if finding.cwe != "CWE-89":
            return []

        query_variable = str(finding.metadata.get("query_variable") or "")
        template_line = int(finding.metadata.get("template_line") or 0)
        execute_line = int(finding.metadata.get("execute_line") or finding.line)
        if not query_variable or template_line < 1:
            return []

        target = target.resolve()
        path = ensure_within(target, target / finding.file)
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=finding.file)

        assignment = self._find_assignment(tree, query_variable, template_line)
        execute = self._find_execute(tree, query_variable, execute_line)
        if assignment is None or execute is None:
            return []
        if not isinstance(assignment.value, ast.JoinedStr):
            return []
        if len(execute.args) != 1 or execute.keywords:
            return []

        query, parameters = self._parameterize(assignment.value)
        if not parameters:
            return []

        lines = source.splitlines()
        assign_indent = lines[assignment.lineno - 1][
            : len(lines[assignment.lineno - 1]) - len(lines[assignment.lineno - 1].lstrip())
        ]
        execute_indent = lines[execute.lineno - 1][
            : len(lines[execute.lineno - 1]) - len(lines[execute.lineno - 1].lstrip())
        ]
        call_name = ast.unparse(execute.func)
        tuple_text = (
            f"({parameters[0]},)"
            if len(parameters) == 1
            else f"({', '.join(parameters)})"
        )
        assignment_replacement = f"{assign_indent}{query_variable} = {query!r}"
        execute_replacement = (
            f"{execute_indent}{call_name}({query_variable}, {tuple_text})"
        )

        original_hash = sha256_file(path)
        edits = [
            TextEdit(
                file=finding.file,
                start_line=assignment.lineno,
                end_line=getattr(assignment, "end_lineno", assignment.lineno),
                replacement=assignment_replacement,
                original_sha256=original_hash,
            ),
            TextEdit(
                file=finding.file,
                start_line=execute.lineno,
                end_line=getattr(execute, "end_lineno", execute.lineno),
                replacement=execute_replacement,
                original_sha256=original_hash,
            ),
        ]
        patched = apply_edits_to_text(source, edits)
        diff = "".join(
            difflib.unified_diff(
                source.splitlines(keepends=True),
                patched.splitlines(keepends=True),
                fromfile=f"a/{finding.file}",
                tofile=f"b/{finding.file}",
            )
        )
        candidate_hash = hashlib.sha256(
            f"{finding.finding_id}\n{diff}".encode("utf-8")
        ).hexdigest()
        changed_lines = sum(
            (edit.end_line - edit.start_line + 1)
            + max(1, len(edit.replacement.splitlines()))
            for edit in edits
        )

        return [
            PatchCandidate(
                candidate_id=f"PATCH-{candidate_hash[:12].upper()}",
                finding_id=finding.finding_id,
                title="Use a parameterized SQL query",
                description=(
                    f"Replace the formatted SQL string in {finding.file} with a driver "
                    "placeholder and pass attacker-controlled values separately."
                ),
                rationale=analysis.recommended_fix,
                expected_security_effect=(
                    "User-controlled values no longer modify SQL syntax and are passed "
                    "as database parameters."
                ),
                edits=edits,
                unified_diff=diff,
                changed_files=[finding.file],
                changed_lines=changed_lines,
                provider=self.name,
                metadata={
                    "query_variable": query_variable,
                    "parameters": parameters,
                    "placeholder_style": "%s",
                    "limitations": [
                        "Assumes a DB-API driver using %s placeholders",
                        "Only patches a simple named f-string query followed by execute(query)",
                    ],
                },
            )
        ]

    @staticmethod
    def _find_assignment(
        tree: ast.AST,
        variable: str,
        expected_line: int,
    ) -> ast.Assign | None:
        candidates: list[ast.Assign] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign):
                continue
            if node.lineno != expected_line:
                continue
            if any(isinstance(target, ast.Name) and target.id == variable for target in node.targets):
                candidates.append(node)
        return candidates[0] if len(candidates) == 1 else None

    @staticmethod
    def _find_execute(
        tree: ast.AST,
        variable: str,
        expected_line: int,
    ) -> ast.Call | None:
        candidates: list[ast.Call] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or node.lineno != expected_line or not node.args:
                continue
            call_name = ast.unparse(node.func).split(".")[-1]
            if call_name not in {"execute", "executemany", "executescript"}:
                continue
            if isinstance(node.args[0], ast.Name) and node.args[0].id == variable:
                candidates.append(node)
        return candidates[0] if len(candidates) == 1 else None

    @staticmethod
    def _parameterize(node: ast.JoinedStr) -> tuple[str, list[str]]:
        query_parts: list[str] = []
        parameters: list[str] = []
        for item in node.values:
            if isinstance(item, ast.Constant) and isinstance(item.value, str):
                query_parts.append(item.value)
            elif isinstance(item, ast.FormattedValue):
                query_parts.append("%s")
                parameters.append(ast.unparse(item.value))
            else:
                raise ValueError("unsupported f-string component")
        return "".join(query_parts), parameters
