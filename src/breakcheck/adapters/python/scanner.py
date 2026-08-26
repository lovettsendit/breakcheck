import ast
import math
from dataclasses import dataclass
from pathlib import Path

from .coverage import make_candidate
from .literals import LiftedLiteral, LiteralRefusal, lift_with_provenance


@dataclass(frozen=True)
class StaticContext:
    module_constants: dict[str, LiftedLiteral]
    imported_names: frozenset[str]


def _is_deeply_immutable(value):
    if type(value) in (type(None), bool, int, str, bytes):
        return True
    if type(value) is float:
        return math.isfinite(value)
    if type(value) is tuple:
        return all(_is_deeply_immutable(item) for item in value)
    return False


class _BindingInventory(ast.NodeVisitor):
    def __init__(self):
        self.bindings = {}
        self.parameters = set()
        self.declarations = set()

    def _bind(self, name):
        if isinstance(name, str) and name:
            self.bindings[name] = self.bindings.get(name, 0) + 1

    def visit_Name(self, node):
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            self._bind(node.id)
        self.generic_visit(node)

    def _visit_arguments(self, arguments):
        for argument in (
            *arguments.posonlyargs,
            *arguments.args,
            *arguments.kwonlyargs,
        ):
            self.parameters.add(argument.arg)
        if arguments.vararg is not None:
            self.parameters.add(arguments.vararg.arg)
        if arguments.kwarg is not None:
            self.parameters.add(arguments.kwarg.arg)

    def visit_FunctionDef(self, node):
        self._bind(node.name)
        self._visit_arguments(node.args)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node):
        self.visit_FunctionDef(node)

    def visit_Lambda(self, node):
        self._visit_arguments(node.args)
        self.generic_visit(node)

    def visit_ClassDef(self, node):
        self._bind(node.name)
        self.generic_visit(node)

    def visit_Import(self, node):
        for alias in node.names:
            self._bind(alias.asname or alias.name.split(".", 1)[0])

    def visit_ImportFrom(self, node):
        for alias in node.names:
            if alias.name != "*":
                self._bind(alias.asname or alias.name)

    def visit_ExceptHandler(self, node):
        self._bind(node.name)
        self.generic_visit(node)

    def visit_Global(self, node):
        self.declarations.update(node.names)

    def visit_Nonlocal(self, node):
        self.declarations.update(node.names)

    def visit_MatchAs(self, node):
        self._bind(node.name)
        self.generic_visit(node)

    def visit_MatchStar(self, node):
        self._bind(node.name)

    def visit_MatchMapping(self, node):
        self._bind(node.rest)
        self.generic_visit(node)


def _imported_names(tree):
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                names.add(alias.asname or alias.name.split(".", 1)[0])
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if alias.name != "*":
                    names.add(alias.asname or alias.name)
    return frozenset(names)


def build_static_context(source):
    if isinstance(source, str):
        tree = ast.parse(source)
    elif isinstance(source, ast.Module):
        tree = source
    else:
        raise ValueError("STATIC_CONTEXT_SOURCE_REFUSED")
    imported_names = _imported_names(tree)
    if any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "globals"
        for node in ast.walk(tree)
    ):
        return StaticContext({}, imported_names)
    inventory = _BindingInventory()
    inventory.visit(tree)
    candidates = {}
    for node in tree.body:
        if (
            isinstance(node, ast.Assign)
            and node.col_offset == 0
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
        ):
            candidates[node.targets[0].id] = node.value
        elif (
            isinstance(node, ast.AnnAssign)
            and node.col_offset == 0
            and isinstance(node.target, ast.Name)
        ):
            if node.value is not None:
                candidates[node.target.id] = node.value
    constants = {}
    for name in sorted(candidates):
        if (
            inventory.bindings.get(name) != 1
            or name in inventory.parameters
            or name in inventory.declarations
            or name in imported_names
        ):
            continue
        try:
            lifted = lift_with_provenance(candidates[name])
        except LiteralRefusal:
            continue
        if _is_deeply_immutable(lifted.value):
            constants[name] = lifted
    return StaticContext(constants, imported_names)


def build_module_constant_table(source):
    return build_static_context(source).module_constants


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

    @staticmethod
    def build_static_context(source_text):
        """Return explicit, AST-only resolution context without changing scan rows."""

        return build_static_context(source_text)

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

        def record_rebinding(local_name, node):
            if local_name in bindings:
                rebound_at[local_name] = min(
                    rebound_at.get(local_name, node.lineno), node.lineno
                )

        for node in ast.walk(tree):
            if isinstance(node, ast.Name) and isinstance(
                node.ctx, (ast.Store, ast.Del)
            ):
                record_rebinding(node.id, node)
            elif isinstance(node, ast.arg):
                record_rebinding(node.arg, node)
            elif isinstance(node, ast.ExceptHandler):
                record_rebinding(node.name, node)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                record_rebinding(node.name, node)
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

    @staticmethod
    def _candidates(call_sites, unsupported):
        rows = []
        for row in call_sites:
            rows.append({**make_candidate(
                api=row["api"],
                file=row["file"],
                line=row["line"],
                column=row["column"],
            ), "reason_code": None})
        for row in unsupported:
            if row.get("reason_code") == "SOURCE_SYNTAX_REFUSED":
                continue
            rows.append({**make_candidate(
                api=row["api"],
                file=row["file"],
                line=row["line"],
                column=row["column"],
            ), "reason_code": row["reason_code"]})
        rows.sort(key=lambda row: (
            row["file"], row["line"], row["column"], row["api"],
            row["candidate_id"],
        ))
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
                    "candidates": [],
                }
            scanner = self if selected_package == self.package_name else type(self)(selected_package)
            result = {
                "imports": scanner.extract_imports(source=source, path=selected_path, package=selected_package),
                "call_sites": scanner.extract_call_sites(source=source, path=selected_path, package=selected_package),
            }
            result["unsupported"] = list(getattr(scanner, "_last_unsupported", ()))
            result["candidates"] = scanner._candidates(
                result["call_sites"], result["unsupported"]
            )
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
        return {
            "imports": imports,
            "call_sites": calls,
            "unsupported": unsupported,
            "candidates": scanner._candidates(calls, unsupported),
        }


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
