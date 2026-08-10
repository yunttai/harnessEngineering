import ast
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class RouteMatch:
    file_path: str
    function_name: str
    line_number: int


def ensure_repository_path(repository_root: Path, candidate: Path) -> Path:
    resolved_root = repository_root.resolve()
    resolved_candidate = (resolved_root / candidate).resolve()
    if resolved_candidate != resolved_root and resolved_root not in resolved_candidate.parents:
        raise ValueError("candidate path escapes repository root")
    return resolved_candidate


def map_flask_route(repository_root: Path, application_root: Path, request_path: str) -> RouteMatch:
    """Map a literal Flask route decorator to its source function."""
    repository_root = repository_root.resolve()
    application_root = ensure_repository_path(repository_root, application_root)
    if not request_path.startswith("/") or ".." in request_path.split("/"):
        raise ValueError("invalid request path")
    for path in sorted(application_root.rglob("*.py")):
        safe_path = ensure_repository_path(repository_root, path)
        tree = ast.parse(safe_path.read_text(encoding="utf-8"), filename=str(safe_path))
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for decorator in node.decorator_list:
                if not isinstance(decorator, ast.Call) or not decorator.args:
                    continue
                route = decorator.args[0]
                if not isinstance(route, ast.Constant) or route.value != request_path:
                    continue
                function = decorator.func
                if isinstance(function, ast.Attribute) and function.attr in {
                    "get",
                    "post",
                    "put",
                    "patch",
                    "delete",
                    "route",
                }:
                    return RouteMatch(
                        file_path=safe_path.relative_to(repository_root).as_posix(),
                        function_name=node.name,
                        line_number=node.lineno,
                    )
    raise LookupError(f"no supported Flask route found for {request_path}")
