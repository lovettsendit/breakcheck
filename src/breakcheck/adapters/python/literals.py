import ast
import keyword


_REFUSAL_CODE = 'NONLITERAL_ARGS'


def _refuse():
    raise ValueError(_REFUSAL_CODE)


def _lift(node):
    if isinstance(node, ast.Constant) and isinstance(node.value, (type(None), bool, int, float, str, bytes)):
        return node.value
    if (isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.UAdd, ast.USub))
            and isinstance(node.operand, ast.Constant)
            and type(node.operand.value) in (int, float)):
        return node.operand.value if isinstance(node.op, ast.UAdd) else -node.operand.value
    if isinstance(node, ast.List):
        return [_lift(item) for item in node.elts]
    if isinstance(node, ast.Tuple):
        return tuple(_lift(item) for item in node.elts)
    if isinstance(node, ast.Dict) and all(key is not None for key in node.keys):
        try:
            return {_lift(key): _lift(value) for key, value in zip(node.keys, node.values)}
        except (TypeError, ValueError):
            _refuse()
    _refuse()


def _call_node(source_text):
    if not isinstance(source_text, str):
        _refuse()
    try:
        node = ast.parse(source_text, mode="eval").body
    except (SyntaxError, ValueError, TypeError):
        _refuse()
    if not isinstance(node, ast.Call):
        _refuse()
    if any(keyword.arg is None for keyword in node.keywords):
        _refuse()
    return node


def lift_literal_args(node):
    if isinstance(node, str):
        call = _call_node(node)
        return [_lift(item) for item in call.args]
    return _lift(node)


def _literal_source(value):
    if value is None or isinstance(value, (bool, int, float, str, bytes)):
        return repr(value)
    if isinstance(value, list):
        return "[" + ", ".join(_literal_source(item) for item in value) + "]"
    if isinstance(value, tuple):
        body = ", ".join(_literal_source(item) for item in value)
        if len(value) == 1:
            body += ","
        return "(" + body + ")"
    if isinstance(value, dict):
        return "{" + ", ".join(_literal_source(key) + ": " + _literal_source(item) for key, item in value.items()) + "}"
    _refuse()


def _call_name(node):
    parts = []
    current = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if not isinstance(current, ast.Name):
        _refuse()
    parts.append(current.id)
    parts.reverse()
    if not all(part.isidentifier() and not keyword.iskeyword(part) for part in parts):
        _refuse()
    return ".".join(parts)


def _import_source(source):
    if not isinstance(source, str):
        _refuse()
    try:
        tree = ast.parse(source, mode="exec")
    except (SyntaxError, ValueError, TypeError):
        _refuse()
    if len(tree.body) != 1 or not isinstance(
        tree.body[0], (ast.Import, ast.ImportFrom)
    ):
        _refuse()
    node = tree.body[0]
    if len(node.names) != 1 or node.names[0].name == "*":
        _refuse()
    alias = node.names[0]
    if alias.asname is not None and (
        not alias.asname.isidentifier() or keyword.iskeyword(alias.asname)
    ):
        _refuse()
    if isinstance(node, ast.Import):
        parts = alias.name.split(".")
        if not all(part.isidentifier() and not keyword.iskeyword(part) for part in parts):
            _refuse()
    else:
        if node.level != 0 or not node.module:
            _refuse()
        module_parts = node.module.split(".")
        if not all(
            part.isidentifier() and not keyword.iskeyword(part)
            for part in module_parts
        ) or not alias.name.isidentifier() or keyword.iskeyword(alias.name):
            _refuse()
    return ast.unparse(node)


def _snippet(call, import_statement):
    api = _call_name(call.func)
    values = [_lift(item) for item in call.args]
    keywords = [(item.arg, _lift(item.value)) for item in call.keywords]
    rendered = [_literal_source(item) for item in values]
    rendered.extend(
        name + "=" + _literal_source(value) for name, value in keywords
    )
    return (
        import_statement
        + "\n\noutcome = "
        + api
        + "("
        + ", ".join(rendered)
        + ")\nprint(repr(outcome))\n"
    )


def synthesize_snippet(*arguments):
    if len(arguments) == 1 and isinstance(arguments[0], str):
        call = _call_node(arguments[0])
        api = _call_name(call.func)
        root = api.split(".", 1)[0]
        return _snippet(call, "import " + root)
    if (
        len(arguments) == 2
        and isinstance(arguments[0], str)
        and isinstance(arguments[1], str)
    ):
        return _snippet(_call_node(arguments[0]), _import_source(arguments[1]))
    if len(arguments) != 2:
        _refuse()
    function_name, node = arguments
    if not isinstance(function_name, str) or not function_name.isidentifier() or keyword.iskeyword(function_name):
        _refuse()
    return function_name + "(" + _literal_source(_lift(node)) + ")"
