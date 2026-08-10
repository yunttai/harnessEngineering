import ast
from pathlib import Path


LAYER_RANK = {
    "types": 0,
    "config": 1,
    "repo": 2,
    "service": 3,
    "runtime": 4,
    "ui": 5,
}


def layer_for_module(module: str) -> str | None:
    parts = module.split(".")
    if len(parts) >= 2 and parts[0] == "attack2patch":
        return parts[1]
    return None


def check_file(path: Path, source_root: Path) -> list[str]:
    relative = path.relative_to(source_root)
    current_layer = relative.parts[1] if len(relative.parts) > 1 else None
    if current_layer not in LAYER_RANK:
        return []
    errors: list[str] = []
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in ast.walk(tree):
        modules: list[str] = []
        if isinstance(node, ast.ImportFrom) and node.module:
            modules.append(node.module)
        elif isinstance(node, ast.Import):
            modules.extend(alias.name for alias in node.names)
        for module in modules:
            imported_layer = layer_for_module(module)
            if imported_layer in LAYER_RANK and LAYER_RANK[imported_layer] > LAYER_RANK[current_layer]:
                errors.append(
                    f"{relative}:{node.lineno}: {current_layer} must not import {imported_layer}"
                )
    return errors


def main() -> int:
    source_root = Path(__file__).parents[1] / "src" / "attack2patch"
    errors = [
        error
        for path in source_root.rglob("*.py")
        for error in check_file(path, source_root.parent)
    ]
    if errors:
        print("\n".join(errors))
        return 1
    print("Architecture dependency check passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
