import ast
from pathlib import Path


def _syntax_refusal(path, exc):
    return {
        "api": "source:" + str(path),
        "line": int(exc.lineno or 0),
        "file": str(path),
        "column": max(int(exc.offset or 1) - 1, 0),
        "reason_code": "SOURCE_SYNTAX_REFUSED",
    }


class PythonUsageScanner:
    def __init__(self, package_name=None):
        if package_name is not None and (not isinstance(package_name, str) or not package_name):
            raise ValueError("PACKAGE_NAME_REFUSED")
        self.package_name = package_name

    def _rooted(self, value):
        return value == self.package_name or value.startswith(self.package_name + ".")

    def _imports(self, tree, file_name):
        bindings = {}
        rows = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if not self._rooted(alias.name):
                        continue
                    local_name = alias.asname or alias.name.split(".")[0]
                    bindings[local_name] = alias.name if alias.asname else alias.name.split(".")[0]
                    rows.append({"module": alias.name, "alias": local_name, "line": node.lineno, "file": file_name})
            elif isinstance(node, ast.ImportFrom) and node.module:
                if not self._rooted(node.module):
                    continue
                for alias in node.names:
                    if alias.name == "*":
                        continue
                    local_name = alias.asname or alias.name
                    bindings[local_name] = node.module + "." + alias.name
                    rows.append({"module": node.module, "alias": local_name, "line": node.lineno, "file": file_name})
        rows.sort(key=lambda row: (row["line"], row["file"], row["module"], row["alias"]))
        return bindings, rows

    def extract_imports(self, source_text=None, file_name=None, *, source=None, path=None, package=None):
        text = source_text if source_text is not None else source
        name = file_name if file_name is not None else path
        root = package if package is not None else self.package_name
        if not isinstance(text, str) or not isinstance(name, str) or not isinstance(root, str) or not root:
            raise ValueError("USAGE_ARGUMENTS_REFUSED")
        scanner = self if root == self.package_name else type(self)(root)
        tree = ast.parse(text, filename=name)
        return scanner._imports(tree, name)[1]

    def extract_call_sites(self, source_text=None, file_name=None, *, source=None, path=None, package=None):
        text = source_text if source_text is not None else source
        name = file_name if file_name is not None else path
        root_package = package if package is not None else self.package_name
        if not isinstance(text, str) or not isinstance(name, str) or not isinstance(root_package, str) or not root_package:
            raise ValueError("USAGE_ARGUMENTS_REFUSED")
        scanner = self if root_package == self.package_name else type(self)(root_package)
        tree = ast.parse(text, filename=name)
        bindings, _ = scanner._imports(tree, name)
        rebound_at = {}
        for node in ast.walk(tree):
            targets = []
            if isinstance(node, ast.Assign):
                targets = list(node.targets)
            elif isinstance(node, (ast.AnnAssign, ast.NamedExpr)):
                targets = [node.target]
            elif isinstance(node, (ast.For, ast.AsyncFor)):
                targets = [node.target]
            for target in targets:
                for child in ast.walk(target):
                    if isinstance(child, ast.Name) and child.id in bindings:
                        rebound_at[child.id] = min(
                            rebound_at.get(child.id, node.lineno), node.lineno
                        )
        rows = []
        unsupported = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if (
                isinstance(node.func, ast.Call)
                and isinstance(node.func.func, ast.Name)
                and node.func.func.id == "getattr"
                and len(node.func.args) >= 2
                and isinstance(node.func.args[0], ast.Name)
                and node.func.args[0].id in bindings
                and isinstance(node.func.args[1], ast.Constant)
                and isinstance(node.func.args[1].value, str)
            ):
                root = node.func.args[0].id
                unsupported.append({
                    "api": bindings[root] + "." + node.func.args[1].value,
                    "line": node.lineno,
                    "file": name,
                    "column": node.col_offset,
                    "reason_code": "DYNAMIC_USAGE_UNSUPPORTED",
                })
                continue
            parts = []
            current = node.func
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            else:
                continue
            parts.reverse()
            if not parts:
                continue
            root = parts[0]
            if root in bindings:
                if node.lineno >= rebound_at.get(root, node.lineno + 1):
                    unsupported.append({
                        "api": bindings[root] + ("." + ".".join(parts[1:]) if len(parts) > 1 else ""),
                        "line": node.lineno,
                        "file": name,
                        "column": node.col_offset,
                        "reason_code": "DYNAMIC_USAGE_UNSUPPORTED",
                    })
                    continue
                qualified = bindings[root] + ("." + ".".join(parts[1:]) if len(parts) > 1 else "")
            elif root == scanner.package_name:
                qualified = ".".join(parts)
            else:
                continue
            if not scanner._rooted(qualified):
                continue
            rows.append({"api": qualified, "line": node.lineno, "file": name, "column": node.col_offset})
        rows.sort(key=lambda row: (row["line"], row["column"], row["api"], row["file"]))
        unsupported.sort(key=lambda row: (row["line"], row["column"], row["api"], row["file"]))
        scanner._last_unsupported = unsupported
        return rows

    def scan(self, repository=None, package_name=None, *, source=None, path=None, package=None, repo=None):
        selected_package = package or package_name or self.package_name
        if source is not None:
            selected_path = path or "<memory>"
            try:
                ast.parse(source, filename=selected_path)
            except SyntaxError as exc:
                return {
                    "imports": [],
                    "call_sites": [],
                    "unsupported": [_syntax_refusal(selected_path, exc)],
                }
            scanner = self if selected_package == self.package_name else type(self)(selected_package)
            result = {
                "imports": scanner.extract_imports(source=source, path=selected_path, package=selected_package),
                "call_sites": scanner.extract_call_sites(source=source, path=selected_path, package=selected_package),
            }
            result["unsupported"] = list(getattr(scanner, "_last_unsupported", ()))
            return result
        root = Path(repository if repository is not None else repo).resolve()
        package = selected_package
        if not isinstance(package, str) or not package:
            raise ValueError("PACKAGE_NAME_REFUSED")
        scanner = self if package == self.package_name else type(self)(package)
        imports = []
        calls = []
        unsupported = []
        for path in sorted(root.rglob("*.py"), key=lambda item: item.as_posix()):
            if path.is_symlink():
                raise ValueError("SYMLINK_ESCAPE_REFUSED")
            relative = path.resolve().relative_to(root).as_posix()
            source_text = path.read_text(encoding="utf-8")
            try:
                ast.parse(source_text, filename=relative)
            except SyntaxError as exc:
                unsupported.append(_syntax_refusal(relative, exc))
                continue
            imports.extend(scanner.extract_imports(source_text, relative))
            calls.extend(scanner.extract_call_sites(source_text, relative))
            unsupported.extend(getattr(scanner, "_last_unsupported", ()))
        imports.sort(key=lambda row: (row["line"], row["file"], row["module"], row["alias"]))
        calls.sort(key=lambda row: (row["line"], row["column"], row["file"], row["api"]))
        unsupported.sort(key=lambda row: (row["line"], row["column"], row["file"], row["api"]))
        return {"imports": imports, "call_sites": calls, "unsupported": unsupported}


def _first(*values):
    return next((value for value in values if value is not None), None)


def _usage_arguments(source=None, path=None, package=None, *, code=None, contents=None,
                     file=None, file_path=None, filename=None, package_name=None,
                     pkg=None, py_path=None, py_text=None, source_path=None,
                     source_text=None, text=None):
    observed_source = _first(source, source_text, text, code, contents, py_text)
    observed_path = _first(path, file_path, file, filename, py_path, source_path)
    observed_package = _first(package, package_name, pkg)
    if not isinstance(observed_source, str) or not isinstance(observed_path, str) or not isinstance(observed_package, str):
        raise ValueError("USAGE_ARGUMENTS_REFUSED")
    return observed_source, observed_path, observed_package


def extract_imports(source=None, path=None, package=None, *, code=None, contents=None,
                   file=None, file_path=None, filename=None, package_name=None,
                   pkg=None, py_path=None, py_text=None, source_path=None,
                   source_text=None, text=None):
    text, name, root = _usage_arguments(source, path, package, code=code, contents=contents,
        file=file, file_path=file_path, filename=filename, package_name=package_name,
        pkg=pkg, py_path=py_path, py_text=py_text, source_path=source_path,
        source_text=source_text, text=text)
    return PythonUsageScanner(root).extract_imports(text, name)


def extract_call_sites(source=None, path=None, package=None, *, code=None, contents=None,
                 file=None, file_path=None, filename=None, package_name=None,
                 pkg=None, py_path=None, py_text=None, source_path=None,
                 source_text=None, text=None):
    text, name, root = _usage_arguments(source, path, package, code=code, contents=contents,
        file=file, file_path=file_path, filename=filename, package_name=package_name,
        pkg=pkg, py_path=py_path, py_text=py_text, source_path=source_path,
        source_text=source_text, text=text)
    return PythonUsageScanner(root).extract_call_sites(text, name)
