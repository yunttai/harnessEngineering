from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from autopatch.runtime.fs import iter_source_files
from autopatch.service.normalization import finding_id_from_fingerprint, make_fingerprint
from autopatch.types import Evidence, Finding, Severity


SQL_KEYWORDS = re.compile(r"\b(select|insert|update|delete|replace|with)\b", re.IGNORECASE)
SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\bghp_[0-9A-Za-z]{36}\b")),
    ("Private key", re.compile(r"-----BEGIN (?:RSA |OPENSSH )?PRIVATE KEY-----")),
    (
        "Generic secret assignment",
        re.compile(
            r"(?i)\b(api[_-]?key|secret|password|token)\b\s*=\s*['\"][^'\"]{12,}['\"]"
        ),
    ),
)


@dataclass(slots=True)
class _SqlTemplate:
    variable: str
    line: int
    end_line: int
    expression: ast.JoinedStr
    formatted_expressions: list[str]
    source_expression: str | None
    function: str | None


class _PythonVisitor(ast.NodeVisitor):
    def __init__(self, *, relative_file: str, source_text: str) -> None:
        self.relative_file = relative_file
        self.source_text = source_text
        self.lines = source_text.splitlines()
        self.function_stack: list[str] = []
        self.tainted: dict[str, str] = {}
        self.sql_templates: dict[str, _SqlTemplate] = {}
        self.findings: list[Finding] = []

    @property
    def function(self) -> str | None:
        return self.function_stack[-1] if self.function_stack else None

    def visit_FunctionDef(self, node: ast.FunctionDef) -> Any:
        self.function_stack.append(node.name)
        previous_tainted = dict(self.tainted)
        previous_templates = dict(self.sql_templates)
        try:
            self.generic_visit(node)
        finally:
            self.tainted = previous_tainted
            self.sql_templates = previous_templates
            self.function_stack.pop()
        return None

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Assign(self, node: ast.Assign) -> Any:
        value = node.value
        targets = [target.id for target in node.targets if isinstance(target, ast.Name)]
        source = self._source_expression(value)
        if source:
            for name in targets:
                self.tainted[name] = source

        if isinstance(value, ast.JoinedStr) and self._looks_like_sql(value):
            formatted = [
                ast.unparse(item.value)
                for item in value.values
                if isinstance(item, ast.FormattedValue)
            ]
            source_expression = next(
                (self.tainted.get(expr) for expr in formatted if expr in self.tainted),
                formatted[0] if formatted else None,
            )
            for name in targets:
                self.sql_templates[name] = _SqlTemplate(
                    variable=name,
                    line=node.lineno,
                    end_line=getattr(node, "end_lineno", node.lineno),
                    expression=value,
                    formatted_expressions=formatted,
                    source_expression=source_expression,
                    function=self.function,
                )

        self.generic_visit(node)
        return None

    def visit_AnnAssign(self, node: ast.AnnAssign) -> Any:
        if isinstance(node.target, ast.Name) and node.value is not None:
            source = self._source_expression(node.value)
            if source:
                self.tainted[node.target.id] = source
        self.generic_visit(node)
        return None

    def visit_Call(self, node: ast.Call) -> Any:
        call_name = self._call_name(node.func)

        if self._is_execute_call(node) and node.args:
            query_arg = node.args[0]
            template: _SqlTemplate | None = None
            if isinstance(query_arg, ast.Name):
                template = self.sql_templates.get(query_arg.id)
            elif isinstance(query_arg, ast.JoinedStr) and self._looks_like_sql(query_arg):
                formatted = [
                    ast.unparse(item.value)
                    for item in query_arg.values
                    if isinstance(item, ast.FormattedValue)
                ]
                template = _SqlTemplate(
                    variable="",
                    line=node.lineno,
                    end_line=getattr(node, "end_lineno", node.lineno),
                    expression=query_arg,
                    formatted_expressions=formatted,
                    source_expression=formatted[0] if formatted else None,
                    function=self.function,
                )

            if template:
                self._add_finding(
                    cwe="CWE-89",
                    finding_type="SQL Injection",
                    severity=Severity.HIGH,
                    rule_id="autopatch.python.formatted-sql-query",
                    message="Formatted SQL query reaches a database execute sink",
                    line=node.lineno,
                    end_line=getattr(node, "end_lineno", node.lineno),
                    source=template.source_expression,
                    sink=call_name,
                    function=template.function or self.function,
                    semantic_key=f"{template.line}:{template.variable}:{','.join(template.formatted_expressions)}",
                    metadata={
                        "query_variable": template.variable,
                        "template_line": template.line,
                        "template_end_line": template.end_line,
                        "execute_line": node.lineno,
                        "execute_end_line": getattr(node, "end_lineno", node.lineno),
                        "formatted_expressions": template.formatted_expressions,
                        "source_expression": template.source_expression,
                    },
                )

        if call_name in {"os.system", "os.popen"} and node.args:
            if not isinstance(node.args[0], ast.Constant):
                self._add_finding(
                    cwe="CWE-78",
                    finding_type="OS Command Injection",
                    severity=Severity.HIGH,
                    rule_id="autopatch.python.dynamic-os-command",
                    message="Dynamic value reaches an operating system command sink",
                    line=node.lineno,
                    end_line=getattr(node, "end_lineno", node.lineno),
                    source=self._source_expression(node.args[0]) or ast.unparse(node.args[0]),
                    sink=call_name,
                    function=self.function,
                    semantic_key=ast.unparse(node.args[0]),
                )

        if call_name in {"subprocess.run", "subprocess.call", "subprocess.Popen"}:
            shell_true = any(
                keyword.arg == "shell"
                and isinstance(keyword.value, ast.Constant)
                and keyword.value.value is True
                for keyword in node.keywords
            )
            if shell_true and node.args and not isinstance(node.args[0], ast.Constant):
                self._add_finding(
                    cwe="CWE-78",
                    finding_type="OS Command Injection",
                    severity=Severity.HIGH,
                    rule_id="autopatch.python.subprocess-shell-true",
                    message="Dynamic subprocess command is executed with shell=True",
                    line=node.lineno,
                    end_line=getattr(node, "end_lineno", node.lineno),
                    source=self._source_expression(node.args[0]) or ast.unparse(node.args[0]),
                    sink=call_name,
                    function=self.function,
                    semantic_key=ast.unparse(node.args[0]),
                )

        if call_name in {"pickle.loads", "pickle.load"} and node.args:
            if not isinstance(node.args[0], ast.Constant):
                self._add_finding(
                    cwe="CWE-502",
                    finding_type="Unsafe Deserialization",
                    severity=Severity.HIGH,
                    rule_id="autopatch.python.unsafe-pickle",
                    message="Potentially untrusted data reaches pickle deserialization",
                    line=node.lineno,
                    end_line=getattr(node, "end_lineno", node.lineno),
                    source=self._source_expression(node.args[0]) or ast.unparse(node.args[0]),
                    sink=call_name,
                    function=self.function,
                    semantic_key=ast.unparse(node.args[0]),
                )

        self.generic_visit(node)
        return None

    def _add_finding(
        self,
        *,
        cwe: str,
        finding_type: str,
        severity: Severity,
        rule_id: str,
        message: str,
        line: int,
        end_line: int,
        source: str | None,
        sink: str | None,
        function: str | None,
        semantic_key: str,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        fingerprint = make_fingerprint(
            scanner="builtin-python",
            rule_id=rule_id,
            cwe=cwe,
            file=self.relative_file,
            line=line,
            semantic_key=semantic_key,
        )
        raw_excerpt = self.lines[line - 1].strip() if 0 < line <= len(self.lines) else None
        evidence = Evidence(
            scanner="builtin-python",
            rule_id=rule_id,
            message=message,
            source=source,
            sink=sink,
            file=self.relative_file,
            line=line,
            raw_excerpt=raw_excerpt,
            metadata=metadata or {},
        )
        self.findings.append(
            Finding(
                finding_id=finding_id_from_fingerprint(fingerprint),
                fingerprint=fingerprint,
                type=finding_type,
                cwe=cwe,
                severity=severity,
                file=self.relative_file,
                line=line,
                end_line=end_line,
                function=function,
                source=source,
                sink=sink,
                scanner="builtin-python",
                rule_id=rule_id,
                message=message,
                evidence=[evidence],
                metadata=metadata or {},
            )
        )

    def _source_expression(self, node: ast.AST) -> str | None:
        call_name = self._call_name(node.func) if isinstance(node, ast.Call) else ""
        if call_name in {
            "input",
            "request.args.get",
            "request.form.get",
            "request.values.get",
            "request.get_json",
            "sys.stdin.read",
        }:
            return call_name
        if isinstance(node, ast.Name):
            return self.tainted.get(node.id)
        if isinstance(node, ast.JoinedStr):
            for item in node.values:
                if isinstance(item, ast.FormattedValue):
                    expression = ast.unparse(item.value)
                    if expression in self.tainted:
                        return self.tainted[expression]
            return ast.unparse(node)
        if isinstance(node, ast.BinOp):
            left = self._source_expression(node.left)
            right = self._source_expression(node.right)
            return left or right
        return None

    @staticmethod
    def _call_name(node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            prefix = _PythonVisitor._call_name(node.value)
            return f"{prefix}.{node.attr}" if prefix else node.attr
        return ""

    @classmethod
    def _is_execute_call(cls, node: ast.Call) -> bool:
        return cls._call_name(node.func).split(".")[-1] in {
            "execute",
            "executemany",
            "executescript",
        }

    @staticmethod
    def _looks_like_sql(node: ast.JoinedStr) -> bool:
        literal = "".join(
            item.value for item in node.values if isinstance(item, ast.Constant)
        )
        return bool(SQL_KEYWORDS.search(literal))


class BuiltinPythonScanner:
    name = "builtin-python"

    def __init__(
        self,
        *,
        required: bool = True,
        excluded_directories: set[str] | None = None,
        max_file_bytes: int = 1_048_576,
    ) -> None:
        self.required = required
        self.excluded_directories = excluded_directories or {
            ".git",
            ".venv",
            "node_modules",
            ".autopatch",
            "dist",
            "build",
            "__pycache__",
        }
        self.max_file_bytes = max_file_bytes

    def available(self) -> bool:
        return True

    def scan(self, target: Path) -> list[Finding]:
        target = target.resolve()
        findings: list[Finding] = []
        files = iter_source_files(
            target,
            suffixes={".py"},
            excluded_directories=self.excluded_directories,
            max_file_bytes=self.max_file_bytes,
        )
        for path in files:
            relative = path.relative_to(target).as_posix()
            source = path.read_text(encoding="utf-8")
            try:
                tree = ast.parse(source, filename=relative)
            except SyntaxError:
                continue
            visitor = _PythonVisitor(relative_file=relative, source_text=source)
            visitor.visit(tree)
            findings.extend(visitor.findings)
            findings.extend(self._scan_secrets(relative, source))
        return findings

    def _scan_secrets(self, relative: str, source: str) -> list[Finding]:
        results: list[Finding] = []
        for line_number, line in enumerate(source.splitlines(), start=1):
            for label, pattern in SECRET_PATTERNS:
                if not pattern.search(line):
                    continue
                rule_id = "autopatch.secret.hardcoded"
                fingerprint = make_fingerprint(
                    scanner=self.name,
                    rule_id=rule_id,
                    cwe="CWE-798",
                    file=relative,
                    line=line_number,
                    semantic_key=label,
                )
                redacted = re.sub(r"(['\"])[^'\"]{4,}\1", r"\1<redacted>\1", line.strip())
                results.append(
                    Finding(
                        finding_id=finding_id_from_fingerprint(fingerprint),
                        fingerprint=fingerprint,
                        type="Hardcoded Secret",
                        cwe="CWE-798",
                        severity=Severity.HIGH,
                        file=relative,
                        line=line_number,
                        function=None,
                        source="source code literal",
                        sink="repository/build artifact",
                        scanner=self.name,
                        rule_id=rule_id,
                        message=f"{label} pattern appears hardcoded",
                        evidence=[
                            Evidence(
                                scanner=self.name,
                                rule_id=rule_id,
                                message=f"{label} pattern appears hardcoded",
                                source="source code literal",
                                sink="repository/build artifact",
                                file=relative,
                                line=line_number,
                                raw_excerpt=redacted,
                                metadata={"secret_type": label},
                            )
                        ],
                        metadata={"secret_type": label},
                    )
                )
        return results
