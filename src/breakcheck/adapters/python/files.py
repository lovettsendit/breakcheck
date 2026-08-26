from pathlib import Path


def iter_python_files(root, *, excluded_paths=()):
    root = Path(root)
    if root.is_symlink():
        raise ValueError("INVENTORY_ROOT_SYMLINK_REFUSED")
    root = root.resolve()
    if not root.exists() or not root.is_dir():
        raise ValueError("INVENTORY_ROOT_REFUSED")
    suffixes = ('.py',)
    excluded_names = ('site-packages', 'venv')
    excluded_prefixes = ()
    excluded = {Path(value).resolve() for value in excluded_paths}
    outputs = []
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
        absolute = path.resolve()
        if any(absolute == item or item in absolute.parents for item in excluded):
            continue
        if path.is_symlink():
            raise ValueError("SYMLINK_ESCAPE_REFUSED")
        relative = path.relative_to(root)
        parts = relative.parts
        if any(part.startswith(".") for part in parts):
            continue
        if any(part in excluded_names for part in parts):
            continue
        relative_name = relative.as_posix()
        if any(relative_name.startswith(prefix) for prefix in excluded_prefixes):
            continue
        if path.is_file() and path.suffix in suffixes:
            outputs.append(path)
    return outputs
