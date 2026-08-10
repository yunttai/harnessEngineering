import ast
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class SQLCodeMatch:
    line_number: int
    vulnerable_code: str
    rule_id: str = "python-sql-string-interpolation"


def scan_file(path: Path) -> list[int]:
    return [match.line_number for match in scan_function(path)]


def scan_function(path: Path, function_name: str | None = None) -> list[SQLCodeMatch]:
    """Find only the supported Python SQL interpolation pattern using the AST."""
    source = path.read_text(encoding="utf-8")
    lines = source.splitlines()
    tree = ast.parse(source, filename=str(path))
    matches: list[SQLCodeMatch] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign) or not isinstance(node.value, ast.JoinedStr):
            continue
        enclosing = _enclosing_function(tree, node)
        if function_name and (not enclosing or enclosing.name != function_name):
            continue
        rendered = ast.get_source_segment(source, node) or lines[node.lineno - 1].strip()
        if "SELECT" not in rendered.upper():
            continue
        matches.append(SQLCodeMatch(line_number=node.lineno, vulnerable_code=rendered))
    return matches


def _enclosing_function(
    tree: ast.AST, target: ast.AST
) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if target in ast.walk(node):
            return node
    return None
