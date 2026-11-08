"""Structural gates over the package source.

Each rule guards a boundary the design depends on: a pure core without I/O, one place that spawns
processes, one place that parses controller JSON, one place that is allowed to disable certificate
verification. The rules are checked on the AST with import aliases resolved, so a violation fails here
before a reviewer sees it. The checkers are also run against a table of known-bad snippets, which keeps
the gate logic itself under test.

The gates stop accidents and the evasions a maintainer would reach for: a module (the process modules and
the import machinery included), an import function or an evaluation function passed around as a value, a
string turned into a module (the import machinery is closed except for the public names of resources and
metadata), a star import (it hides the names it binds), and the interpreter's globals and import machinery
reached by name, by attribute or by string. They do not model a module reached as the attribute of another
module (`typing.sys.modules`), object introspection, a library that evaluates or resolves a string or
serialized code, or names computed at run time.
"""

import ast
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest

import unifiwifioptimizer

PACKAGE_ROOT = Path(unifiwifioptimizer.__file__).parent
PACKAGE = "unifiwifioptimizer"

CORE_PACKAGES = frozenset({"domain", "rf", "compliance", "analysis", "ports"})
# Direction inside the core: the domain is the leaf, rf and ports build on it alone, compliance on rf, analysis
# on everything but ports. An edge that is not listed is a violation.
CORE_IMPORTS_ALLOWED: dict[str, frozenset[str]] = {
    "domain": frozenset(),
    "rf": frozenset({"domain"}),
    "ports": frozenset({"domain"}),
    "compliance": frozenset({"domain", "rf"}),
    "analysis": frozenset({"domain", "rf", "compliance"}),
}
# Outside the core: the report is data plus text and never reaches an adapter or the command line; the
# application layer never imports the composition root.
LAYER_IMPORTS_FORBIDDEN: dict[str, frozenset[str]] = {
    "report": frozenset({"adapters", "cli"}),
    "app": frozenset({"cli"}),
}
# The only standard-library modules the core may import: pure data, math and typing. Anything that can
# touch a socket, a file, a process or the environment is absent on purpose.
CORE_ALLOWED_STDLIB = frozenset(
    {
        "__future__",
        "abc",
        "collections",
        "dataclasses",
        "datetime",
        "decimal",
        "enum",
        "fractions",
        "functools",
        "hashlib",
        "hmac",
        "ipaddress",
        "itertools",
        "math",
        "operator",
        "re",
        "base64",
        "statistics",
        "string",
        "textwrap",
        "types",
        "typing",
    }
)
SUBPROCESS_ALLOWED = frozenset({"adapters/ssh/openssh.py", "adapters/ssh/hostkeys.py"})
JSON_ALLOWED = frozenset({"adapters/unifi/client.py"})
SSL_ALLOWED = frozenset({"adapters/unifi/tls.py"})
TLS_BYPASS_ALLOWED = ("adapters/unifi/tls.py", "PinnedHTTPSConnection", "__init__")

# `breakpoint` runs whatever PYTHONBREAKPOINT names, the entry point does not isolate the environment.
DYNAMIC_IMPORTS = frozenset(
    {"__import__", "builtins.__import__", "breakpoint", "sys.breakpointhook", "sys.__breakpointhook__"}
)
# The import machinery as a whole is closed: anything that turns a name, a path or an entry point into a module.
# Only the resource and version lookups the package needs stay open.
IMPORT_MACHINERY = frozenset({"imp", "importlib", "pkgutil", "pydoc", "runpy", "zipimport"})
IMPORT_MACHINERY_OPEN = frozenset({"importlib.metadata", "importlib.metadata.version"})
# importlib.resources stays open for its public names; a private module below it resolves any name to a module.
IMPORT_MACHINERY_OPEN_PREFIX = "importlib.resources"
# Attributes that lead from any object back to the interpreter's globals or its import machinery, whatever module
# the object came from.
INTERPRETER_REACH_ATTRIBUTES = frozenset(
    {
        "__builtins__",
        "__globals__",
        "__import__",
        "__self__",
        "__loader__",
        "__spec__",
        "f_builtins",
        "f_globals",
        "f_locals",
    }
)
# Reaching a module or an import function without naming it at a call: the module object handed on as a value, and
# the lookups that turn a string into a module.
LOOKUP_MODULES = frozenset({"importlib", "importlib.metadata", "importlib.resources", "builtins", "sys"})
REFLECTION_NAMES = frozenset(
    {
        "__builtins__",
        "__loader__",
        "__spec__",
        "sys.modules",
        "sys.meta_path",
        "sys.path_hooks",
        "sys.path_importer_cache",
        "globals",
        "locals",
        "vars",
    }
)
SHELL_CALLS = frozenset(
    {
        "eval",
        "exec",
        "compile",
        "os.system",
        "os.popen",
        "pty.spawn",
        "asyncio.create_subprocess_shell",
        "asyncio.subprocess.create_subprocess_shell",
        "subprocess.getoutput",
        "subprocess.getstatusoutput",
    }
)
SHELL_CALL_PREFIXES = ("os.exec", "os.spawn", "os.posix_spawn")
# Event-loop spawn methods; the loop's type is not statically resolvable, so the attribute name alone counts.
LOOP_SPAWN_ATTRIBUTES = frozenset({"subprocess_exec", "subprocess_shell"})
# The transports and the private loop method start a process with a positional `shell` flag, so the keyword rule
# never sees it.
ASYNCIO_PRIVATE_SPAWN = frozenset(
    {"base_subprocess", "unix_events", "windows_events", "windows_utils", "_make_subprocess_transport"}
)
PROCESS_SPAWN_PREFIXES = (
    "subprocess.",
    "asyncio.create_subprocess",
    "asyncio.subprocess.",
    "multiprocessing.",
    "concurrent.futures.process.",
)
PROCESS_SPAWN_ROOTS = frozenset({"subprocess", "asyncio"})
# Process creation that bypasses subprocess entirely; none of it has a place in this tool.
PROCESS_CREATION_NAMES = frozenset(
    {"os.fork", "os.forkpty", "pty.fork", "concurrent.futures.ProcessPoolExecutor", "os.posix_spawn", "os.posix_spawnp"}
)
PROCESS_MODULES = frozenset({"subprocess", "multiprocessing"})
# Handing one of these modules on as a value (`o = os; o.system(c)`, `getattr(os, "system")`) reaches the names
# above without a chain the checks can read. The set is derived from those name lists, so it cannot drift from them.
SPAWN_VALUE_MODULES = frozenset(
    name.rsplit(".", 1)[0]
    for name in (*SHELL_CALLS, *PROCESS_CREATION_NAMES, *SHELL_CALL_PREFIXES, *PROCESS_SPAWN_PREFIXES)
    if "." in name
)
# The modules behind os and subprocess (and pty, which spawns a child itself) expose the same calls under other names.
SPAWN_PRIVATE_MODULES = frozenset({"posix", "nt", "_posixsubprocess", "pty"})
# `env` counts as an interpreter: a local spawn passes its environment via `env=`, never through env(1).
SHELL_INTERPRETERS = frozenset(
    {"sh", "ash", "bash", "dash", "zsh", "ksh", "mksh", "csh", "tcsh", "fish", "busybox", "env"}
)
# Outside the client, json may only serialise; every other reference into json or _json is a parser.
JSON_WRITE_ALLOWED = frozenset({"json.dump", "json.dumps", "json.JSONEncoder", "json.JSONDecodeError"})
# The explicit bypass constants plus every public ssl entry point known to produce an unverified
# connection or context by default.
TLS_BYPASS_NAMES = frozenset(
    {
        "ssl.CERT_NONE",
        "ssl.VerifyMode",
        "ssl._create_unverified_context",
        "ssl._create_stdlib_context",
        "ssl.Purpose.CLIENT_AUTH",
        "ssl.PROTOCOL_TLS_SERVER",
        "ssl.PROTOCOL_TLS",
        "ssl.PROTOCOL_SSLv23",
        "ssl.get_server_certificate",
        "ssl.wrap_socket",
    }
)
TLS_BYPASS_ATTRIBUTES = frozenset({"check_hostname", "verify_mode"})
TLS_BYPASS_STRINGS = frozenset(name.rsplit(".", 1)[1] for name in TLS_BYPASS_NAMES) | TLS_BYPASS_ATTRIBUTES

Checker = Callable[[ast.Module, str], list[str]]


def source_files() -> list[Path]:
    return sorted(PACKAGE_ROOT.rglob("*.py"))


def relative(path: Path) -> str:
    return path.relative_to(PACKAGE_ROOT).as_posix()


def layer_of(relpath: str) -> str:
    parts = relpath.split("/")
    return parts[0] if len(parts) > 1 else ""


def module_name_of(relpath: str) -> str:
    parts = relpath.removesuffix(".py").split("/")
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join([PACKAGE, *parts])


def parse(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def absolute_module(node: ast.ImportFrom, relpath: str) -> str:
    if node.level == 0:
        return node.module or ""
    package_parts = module_name_of(relpath).split(".")
    if not relpath.endswith("__init__.py"):
        package_parts = package_parts[:-1]
    base = package_parts[: len(package_parts) - (node.level - 1)]
    return ".".join([*base, node.module] if node.module else base)


Aliases = dict[str, frozenset[str]]


def aliases_of(tree: ast.Module, relpath: str) -> Aliases:
    """Local name → every origin it is bound to anywhere in the module.

    Scopes are deliberately ignored: a name bound to two origins (a module-level `import subprocess as sp`
    and a function-local `import math as sp`) resolves to both, so a checker sees the dangerous one no
    matter which binding is in effect at the use site.
    """
    aliases: dict[str, set[str]] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                local = alias.asname or alias.name.split(".")[0]
                aliases.setdefault(local, set()).add(alias.name if alias.asname else alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            module = absolute_module(node, relpath)
            for alias in node.names:
                origin = f"{module}.{alias.name}" if module else alias.name
                aliases.setdefault(alias.asname or alias.name, set()).add(origin)
    return {name: frozenset(origins) for name, origins in aliases.items()}


def imported_modules(tree: ast.Module, relpath: str) -> Iterator[tuple[str, list[str]]]:
    """(absolute module, imported names) for every import statement."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                yield alias.name, []
        elif isinstance(node, ast.ImportFrom):
            yield absolute_module(node, relpath), [alias.name for alias in node.names]


def qualified_names(node: ast.expr, aliases: Aliases, *, through_calls: bool = True) -> frozenset[str]:
    """Every dotted origin a name/attribute chain may denote, e.g. `s.CERT_NONE` → {`ssl.CERT_NONE`}.

    With `through_calls` the chain continues into a call's callee (`ssl.SSLContext().x` → `ssl.SSLContext.x`);
    without it a call ends the chain, so an attribute of a call's result is not attributed to the callee.
    """
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Call):
        if not through_calls:
            return frozenset()
        node = node.func
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
    if not isinstance(node, ast.Name):
        return frozenset()
    suffix = list(reversed(parts))
    return frozenset(".".join([origin, *suffix]) for origin in aliases.get(node.id, frozenset({node.id})))


def calls(tree: ast.Module, aliases: Aliases) -> Iterator[tuple[ast.Call, frozenset[str]]]:
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            yield node, qualified_names(node.func, aliases)


def enclosing_function(tree: ast.Module, target: ast.AST) -> tuple[str, str]:
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            for item in node.body:
                if isinstance(item, ast.FunctionDef) and any(sub is target for sub in ast.walk(item)):
                    return node.name, item.name
    return "", ""


def check_core_imports(tree: ast.Module, relpath: str) -> list[str]:
    layer = layer_of(relpath)
    if layer not in CORE_PACKAGES:
        return []
    found: list[str] = []
    for module, names in imported_modules(tree, relpath):
        root = module.split(".")[0]
        if root == PACKAGE:
            layers = [module.split(".")[1]] if "." in module else names
            if not layers:
                found.append(f"imports the bare {PACKAGE} package")
            for imported in layers:
                if imported not in CORE_PACKAGES:
                    found.append(f"imports {PACKAGE}.{imported}, which is not a core package")
                elif imported != layer and imported not in CORE_IMPORTS_ALLOWED[layer]:
                    found.append(f"imports {PACKAGE}.{imported}, against the core direction ({layer} may not)")
        elif root not in CORE_ALLOWED_STDLIB:
            found.append(f"imports {module}, which is not on the core allowlist")
    return found


def check_layer_imports(tree: ast.Module, relpath: str) -> list[str]:
    layer = layer_of(relpath)
    forbidden = LAYER_IMPORTS_FORBIDDEN.get(layer)
    if forbidden is None:
        return []
    found: list[str] = []
    for module, names in imported_modules(tree, relpath):
        if module.split(".")[0] != PACKAGE:
            continue
        layers = [module.split(".")[1]] if "." in module else names
        found.extend(
            f"imports {PACKAGE}.{imported}, which {layer} may not" for imported in layers if imported in forbidden
        )
    return found


def modules_used_as_values(tree: ast.Module, aliases: Aliases, modules: frozenset[str]) -> list[str]:
    """Imported modules in `modules` that appear as a value instead of the base of an attribute access.

    `getattr(json, "loads")`, `vars(json)` and `j = json` reach the module's contents without a `json.<name>`
    chain, which the attribute-based rules cannot see; a submodule reference (`getattr(importlib.metadata, ...)`)
    is the same thing one level down. A bare name counts only when an import bound it, so a parameter that
    happens to be called `json` is not the module.
    """
    attribute_bases = {id(node.value) for node in ast.walk(tree) if isinstance(node, ast.Attribute)}
    found: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Name | ast.Attribute) or not isinstance(node.ctx, ast.Load):
            continue
        if id(node) in attribute_bases or (isinstance(node, ast.Name) and node.id not in aliases):
            continue
        found.extend(f"uses {origin} as a value" for origin in sorted(qualified_names(node, aliases) & modules))
    return found


def in_closed_machinery(name: str) -> bool:
    if name.startswith(IMPORT_MACHINERY_OPEN_PREFIX):
        return any(part.startswith("_") for part in name.split("."))
    return name.split(".")[0] in IMPORT_MACHINERY and name not in IMPORT_MACHINERY_OPEN


def machinery_import_problem(module: str, names: list[str]) -> bool:
    """Whether an import statement reaches the closed import machinery, judged name by name for a from-import."""
    if module == "importlib":
        return not names or not set(names) <= {"resources", "metadata"}
    if module == "importlib.metadata":
        return not set(names) <= {"version"}
    if module.startswith(IMPORT_MACHINERY_OPEN_PREFIX):
        return in_closed_machinery(module) or any(n == "*" or n.startswith("_") for n in names)
    return in_closed_machinery(module)


def check_dynamic_imports(tree: ast.Module, relpath: str) -> list[str]:
    aliases = aliases_of(tree, relpath)
    found = modules_used_as_values(tree, aliases, LOOKUP_MODULES)
    for module, names in imported_modules(tree, relpath):
        if machinery_import_problem(module, names) or module.split(".")[0] == "builtins":
            found.append(f"imports {module}")
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and node.value in INTERPRETER_REACH_ATTRIBUTES:
            found.append(f"names {node.value}, which looks it up by string")
        if not isinstance(node, ast.Name | ast.Attribute):
            continue
        for name in qualified_names(node, aliases, through_calls=False):
            if name in DYNAMIC_IMPORTS or (name not in IMPORT_MACHINERY and in_closed_machinery(name)):
                found.append(f"dynamic import via {name}")
            elif name in REFLECTION_NAMES:
                found.append(f"reflective module lookup via {name}")
        if isinstance(node, ast.Attribute) and node.attr in INTERPRETER_REACH_ATTRIBUTES:
            found.append(f"reaches the interpreter through .{node.attr}")
    return found


def is_spawn_import(module: str, names: list[str]) -> bool:
    if module.split(".")[0] in PROCESS_MODULES or module.startswith("asyncio.subprocess"):
        return True
    if module == "asyncio" and any(n == "subprocess" or n.startswith("create_subprocess") for n in names):
        return True
    if module.startswith("concurrent.futures.process"):
        return True
    return module == "concurrent.futures" and any(n in {"ProcessPoolExecutor", "process"} for n in names)


def check_process_spawn_location(tree: ast.Module, relpath: str) -> list[str]:
    if relpath in SUBPROCESS_ALLOWED:
        return []
    aliases = aliases_of(tree, relpath)
    found = [f"imports {module}" for module, names in imported_modules(tree, relpath) if is_spawn_import(module, names)]
    for _call, names in calls(tree, aliases):
        found.extend(f"calls {n}" for n in names if n.startswith(PROCESS_SPAWN_PREFIXES) or n in PROCESS_CREATION_NAMES)
    for node in ast.walk(tree):
        if isinstance(node, ast.Name | ast.Attribute):
            found.extend(f"references {n}" for n in qualified_names(node, aliases) & PROCESS_CREATION_NAMES)
        if isinstance(node, ast.Attribute) and node.attr in LOOP_SPAWN_ATTRIBUTES:
            found.append(f"references .{node.attr}")
    return found


def literal_argv(call: ast.Call) -> list[str]:
    """Leading string constants of the spawned argv: a list/tuple literal (first positional or `args=`) or
    the positional varargs of `asyncio.create_subprocess_exec` / `loop.subprocess_exec(protocol, ...)`."""
    elements: list[ast.expr] = list(call.args)
    if isinstance(call.func, ast.Attribute) and call.func.attr == "subprocess_exec":
        elements = elements[1:]
    for keyword in call.keywords:
        if keyword.arg == "args":
            elements = [keyword.value]
    if elements and isinstance(elements[0], ast.List | ast.Tuple):
        elements = list(elements[0].elts)
    words: list[str] = []
    for element in elements:
        if not (isinstance(element, ast.Constant) and isinstance(element.value, str)):
            break
        words.append(element.value)
    return words


def program_of(words: list[str]) -> str:
    return words[0].rsplit("/", 1)[-1] if words else ""


def spawns_an_interpreter(call: ast.Call) -> bool:
    # No local shell is ever legitimate: the remote `sh -s` runs behind `ssh`, whose argv[0] is `ssh`.
    return program_of(literal_argv(call)) in SHELL_INTERPRETERS


def check_shell_execution(tree: ast.Module, relpath: str) -> list[str]:
    aliases = aliases_of(tree, relpath)
    found = modules_used_as_values(tree, aliases, SPAWN_VALUE_MODULES)
    found.extend(
        f"imports {module}"
        for module, _ in imported_modules(tree, relpath)
        if module.split(".")[0] in SPAWN_PRIVATE_MODULES
    )
    found.extend(
        f"imports {module}"
        for module, names in imported_modules(tree, relpath)
        if (module.startswith("asyncio.") and module.split(".")[1] in ASYNCIO_PRIVATE_SPAWN)
        or (module == "asyncio" and ASYNCIO_PRIVATE_SPAWN.intersection(names))
    )
    for node in ast.walk(tree):
        # A reference, not only a call: `run = os.system` or `partial(exec, src)` runs the same code later.
        if isinstance(node, ast.Attribute) and node.attr == "subprocess_shell":
            found.append("references .subprocess_shell")
        if isinstance(node, ast.Attribute) and node.attr in ASYNCIO_PRIVATE_SPAWN:
            found.append(f"references .{node.attr}")
        if isinstance(node, ast.Name | ast.Attribute):
            found.extend(
                f"references {n}"
                for n in qualified_names(node, aliases, through_calls=False)
                if n in SHELL_CALLS or n.startswith(SHELL_CALL_PREFIXES)
            )
    for call, names in calls(tree, aliases):
        label = "/".join(sorted(names)) or "<call>"
        is_spawn = any(n.split(".")[0] in PROCESS_SPAWN_ROOTS for n in names) or (
            isinstance(call.func, ast.Attribute) and call.func.attr in LOOP_SPAWN_ATTRIBUTES
        )
        if is_spawn and spawns_an_interpreter(call):
            found.append(f"{label} runs a shell interpreter")
        for keyword in call.keywords:
            if keyword.arg == "shell" and not (
                isinstance(keyword.value, ast.Constant) and keyword.value.value is False
            ):
                found.append(f"passes shell= to {label}")
            if keyword.arg is None and is_spawn:
                found.append(f"passes **kwargs to {label}")
    return found


def check_json_parse_location(tree: ast.Module, relpath: str) -> list[str]:
    if relpath in JSON_ALLOWED:
        return []
    aliases = aliases_of(tree, relpath)
    found: list[str] = []
    for module, names in imported_modules(tree, relpath):
        if module.split(".")[0] == "_json" or module.startswith("json."):
            found.append(f"imports {module}")
        elif module == "json":
            found.extend(
                f"imports json.{n}, which is not a JSON writer" for n in names if f"json.{n}" not in JSON_WRITE_ALLOWED
            )
    for node in ast.walk(tree):
        if not isinstance(node, ast.Name | ast.Attribute):
            continue
        # A call ends the chain: `json.dumps(x).encode()` is a str method, not a json reference.
        for name in qualified_names(node, aliases, through_calls=False):
            if name.split(".")[0] in {"json", "_json"} and name != "json" and name not in JSON_WRITE_ALLOWED:
                found.append(f"references {name}, which is not a JSON writer")
    found.extend(modules_used_as_values(tree, aliases, frozenset({"json", "_json"})))
    return found


def check_ssl_location(tree: ast.Module, relpath: str) -> list[str]:
    if relpath in SSL_ALLOWED:
        return []
    return [
        f"imports {module}" for module, _ in imported_modules(tree, relpath) if module.split(".")[0] in {"ssl", "_ssl"}
    ]


def check_tls_bypass_confinement(tree: ast.Module, relpath: str) -> list[str]:
    aliases = aliases_of(tree, relpath)
    allowed_file, allowed_class, allowed_function = TLS_BYPASS_ALLOWED
    found: list[str] = []
    for node in ast.walk(tree):
        reason = ""
        if isinstance(node, ast.Call) and "ssl.SSLContext" in qualified_names(node.func, aliases):
            protocol = (
                node.args[0] if node.args else next((k.value for k in node.keywords if k.arg == "protocol"), None)
            )
            if protocol is None or qualified_names(protocol, aliases) != {"ssl.PROTOCOL_TLS_CLIENT"}:
                found.append("builds ssl.SSLContext without PROTOCOL_TLS_CLIENT")
        if isinstance(node, ast.Name | ast.Attribute) and (hits := qualified_names(node, aliases) & TLS_BYPASS_NAMES):
            reason = f"uses {'/'.join(sorted(hits))}"
        elif isinstance(node, ast.Assign | ast.AnnAssign | ast.AugAssign):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            attrs = [t.attr for t in targets if isinstance(t, ast.Attribute) and t.attr in TLS_BYPASS_ATTRIBUTES]
            if attrs:
                reason = f"assigns {', '.join(attrs)}"
        elif isinstance(node, ast.Constant) and node.value in TLS_BYPASS_STRINGS:
            reason = f"names {node.value!r} as a string"
        if reason and (relpath, *enclosing_function(tree, node)) != (allowed_file, allowed_class, allowed_function):
            found.append(f"{reason} outside {allowed_class}.{allowed_function}")
    return found


SPAWN_ENV_REQUIRED = frozenset(
    {"subprocess.run", "subprocess.Popen", "subprocess.call", "subprocess.check_call", "subprocess.check_output"}
)


def check_spawn_env(tree: ast.Module, relpath: str) -> list[str]:
    """Every process the SSH adapters start gets an explicit environment: `env=` absent (the parent's
    environment, credentials included, would be inherited), `env=None` (the same) or hidden behind `**kwargs`
    are all violations."""
    if not relpath.startswith("adapters/ssh/"):
        return []
    aliases = aliases_of(tree, relpath)
    found = []
    for call, names in calls(tree, aliases):
        if not names & SPAWN_ENV_REQUIRED:
            continue
        env = next((k for k in call.keywords if k.arg == "env"), None)
        if env is None:
            found.append("spawns a process without an explicit env=")
        elif isinstance(env.value, ast.Constant) and env.value.value is None:
            found.append("spawns a process with env=None, which inherits the parent's environment")
    return found


def check_star_imports(tree: ast.Module, relpath: str) -> list[str]:
    # A star import binds names that alias resolution cannot see, so every rule keyed on a resolved name is blind
    # to what it brings in.
    return [
        f"star-imports {absolute_module(node, relpath)}"
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and any(alias.name == "*" for alias in node.names)
    ]


CHECKERS: dict[str, Checker] = {
    "core-imports": check_core_imports,
    "dynamic-imports": check_dynamic_imports,
    "layer-imports": check_layer_imports,
    "process-spawn-location": check_process_spawn_location,
    "spawn-env-required": check_spawn_env,
    "star-imports": check_star_imports,
    "shell-execution": check_shell_execution,
    "json-parse-location": check_json_parse_location,
    "ssl-location": check_ssl_location,
    "tls-bypass-confinement": check_tls_bypass_confinement,
}


def test_the_core_has_source_files() -> None:
    assert any(layer_of(relative(p)) in CORE_PACKAGES for p in source_files())


@pytest.mark.parametrize("path", source_files(), ids=relative)
@pytest.mark.parametrize("checker", CHECKERS.values(), ids=list(CHECKERS))
@pytest.mark.security("T1", "T9", "T16")
def test_source_file_passes_every_gate(path: Path, checker: Checker) -> None:
    assert checker(parse(path), relative(path)) == []


BAD_SNIPPETS: list[tuple[str, str, str]] = [
    ("core-imports", "rf/x.py", "import subprocess\n"),
    ("core-imports", "rf/x.py", "import logging\n"),
    ("core-imports", "rf/x.py", "import importlib\n"),
    ("core-imports", "domain/x.py", "from unifiwifioptimizer.config import loader\n"),
    ("core-imports", "domain/x.py", "from unifiwifioptimizer import cli\n"),
    ("core-imports", "domain/x.py", "from .. import adapters\n"),
    ("core-imports", "domain/x.py", "from ..adapters.ssh import openssh\n"),
    ("core-imports", "ports/x.py", "from ...unifiwifioptimizer.report import text\n"),
    ("core-imports", "rf/x.py", "from unifiwifioptimizer.storage import x\n"),
    ("core-imports", "rf/x.py", "from unifiwifioptimizer import __main__\n"),
    ("core-imports", "rf/x.py", "import unifiwifioptimizer\n"),
    ("core-imports", "rf/x.py", "import uuid\n"),
    ("core-imports", "domain/x.py", "from unifiwifioptimizer.rf import corridor\n"),
    ("core-imports", "domain/x.py", "from unifiwifioptimizer.rf.roaming import RoamingCap\n"),
    ("core-imports", "rf/x.py", "from unifiwifioptimizer.compliance import engine\n"),
    ("core-imports", "ports/x.py", "from unifiwifioptimizer.rf import corridor\n"),
    ("core-imports", "compliance/x.py", "from unifiwifioptimizer.analysis import txpower\n"),
    ("core-imports", "compliance/x.py", "from unifiwifioptimizer.ports import controller\n"),
    ("core-imports", "analysis/x.py", "from unifiwifioptimizer import ports\n"),
    ("layer-imports", "report/x.py", "from unifiwifioptimizer.adapters.unifi import client\n"),
    ("layer-imports", "report/x.py", "from unifiwifioptimizer import cli\n"),
    ("layer-imports", "app/x.py", "from unifiwifioptimizer.cli.exit_codes import ExitCode\n"),
    ("dynamic-imports", "cli/x.py", "import importlib\nimportlib.import_module('subprocess')\n"),
    ("dynamic-imports", "cli/x.py", "__import__('subprocess')\n"),
    ("dynamic-imports", "cli/x.py", "from importlib import import_module as im\nim('os')\n"),
    ("dynamic-imports", "cli/x.py", "from builtins import __import__ as imp\nimp('subprocess')\n"),
    ("dynamic-imports", "cli/x.py", "import builtins\nbuiltins.__import__('subprocess')\n"),
    ("dynamic-imports", "cli/x.py", "import importlib\nim = importlib.import_module\nim('json')\n"),
    ("dynamic-imports", "cli/x.py", "import importlib\ngetattr(importlib, 'import_module')('json')\n"),
    ("dynamic-imports", "cli/x.py", "import builtins\ngetattr(builtins, '__import__')('json')\n"),
    ("dynamic-imports", "rf/x.py", "__builtins__.__import__('subprocess')\n"),
    ("dynamic-imports", "rf/x.py", "__builtins__['__import__']('subprocess')\n"),
    ("dynamic-imports", "cli/x.py", "import sys\nsys.modules['json'].loads(x)\n"),
    ("dynamic-imports", "cli/x.py", "import sys\ngetattr(sys, 'modules')['json']\n"),
    ("dynamic-imports", "cli/x.py", "import json\nglobals()['json'].loads(x)\n"),
    ("dynamic-imports", "cli/x.py", "import json\nvars(json)\n"),
    ("dynamic-imports", "cli/x.py", "import pkgutil\npkgutil.resolve_name('json.loads')\n"),
    ("dynamic-imports", "cli/x.py", "import pydoc\npydoc.locate('json.loads')\n"),
    ("dynamic-imports", "cli/x.py", "import importlib.util\nimportlib.util.find_spec('json')\n"),
    ("dynamic-imports", "cli/x.py", "import runpy\nrunpy.run_module('json')\n"),
    ("dynamic-imports", "rf/x.py", "import re\nre.__builtins__['__import__']('subprocess')\n"),
    ("dynamic-imports", "rf/x.py", "import re\nre.escape.__globals__['x']\n"),
    ("dynamic-imports", "rf/x.py", "import re\ngetattr(re, '__builtins__')['__import__']('subprocess')\n"),
    ("dynamic-imports", "rf/x.py", "import re\nre.__dict__['__builtins__']['__import__']('subprocess')\n"),
    ("dynamic-imports", "cli/x.py", "getattr(f, '__globals__')\n"),
    (
        "dynamic-imports",
        "cli/x.py",
        "from importlib.metadata import EntryPoint\nEntryPoint('a', 'json:loads', 'g').load()\n",
    ),
    ("dynamic-imports", "cli/x.py", "import pkgutil\npkgutil.get_loader('json')\n"),
    (
        "dynamic-imports",
        "cli/x.py",
        "import importlib.machinery\nimportlib.machinery.SourceFileLoader('a', p).load_module()\n",
    ),
    ("dynamic-imports", "cli/x.py", "import imp\nimp.load_source('a', p)\n"),
    ("dynamic-imports", "cli/x.py", "import zipimport\nzipimport.zipimporter(p)\n"),
    ("dynamic-imports", "cli/x.py", "import importlib\n"),
    ("dynamic-imports", "cli/x.py", "import importlib.metadata\nimportlib.machinery.SourceFileLoader\n"),
    ("dynamic-imports", "cli/x.py", "from importlib.resources import _common\n"),
    ("dynamic-imports", "cli/x.py", "from importlib.resources import *\n"),
    ("dynamic-imports", "cli/x.py", "from importlib.metadata import *\n"),
    ("dynamic-imports", "cli/x.py", "from importlib.metadata import EntryPoint\n"),
    ("dynamic-imports", "cli/x.py", "import importlib.resources._common\n"),
    ("dynamic-imports", "cli/x.py", "import importlib.resources\nimportlib.resources._common.x\n"),
    ("dynamic-imports", "cli/x.py", "import sys\nsys.meta_path.append(f)\n"),
    ("dynamic-imports", "cli/x.py", "import sys\nsys.path_hooks.append(f)\n"),
    ("dynamic-imports", "cli/x.py", "import sys\nsys.path_importer_cache.clear()\n"),
    ("dynamic-imports", "cli/x.py", "import importlib.metadata\ngetattr(importlib.metadata, 'x')\n"),
    ("dynamic-imports", "cli/x.py", "from importlib import metadata\nvars(metadata)\n"),
    ("dynamic-imports", "cli/x.py", "from importlib import resources\nr = resources\n"),
    ("dynamic-imports", "cli/x.py", "import importlib.resources\nr = importlib.resources\n"),
    ("dynamic-imports", "cli/x.py", "import builtins\n"),
    ("dynamic-imports", "cli/x.py", "from builtins import open\n"),
    ("shell-execution", "cli/x.py", "import os\ngetattr(os, 'system')(cmd)\n"),
    ("shell-execution", "cli/x.py", "import os\no = os\no.system(cmd)\n"),
    ("shell-execution", "cli/x.py", "import os\nvars(os)['system'](cmd)\n"),
    ("shell-execution", "cli/x.py", "import asyncio\nasyncio.subprocess\n"),
    ("shell-execution", "cli/x.py", "import asyncio\ngetattr(asyncio, 'create_subprocess_shell')(cmd)\n"),
    ("shell-execution", "cli/x.py", "import pty\npty.spawn(['sh'])\n"),
    ("shell-execution", "cli/x.py", "import posix\nposix.system(cmd)\n"),
    ("shell-execution", "cli/x.py", "import nt\nnt.system(cmd)\n"),
    ("shell-execution", "cli/x.py", "import _posixsubprocess\n"),
    ("shell-execution", "cli/x.py", "from posix import system\n"),
    ("star-imports", "cli/x.py", "from os import *\nsystem(cmd)\n"),
    ("star-imports", "adapters/unifi/tls.py", "from ssl import *\n"),
    ("star-imports", "cli/x.py", "from asyncio import *\n"),
    ("star-imports", "cli/x.py", "from . import *\n"),
    ("dynamic-imports", "cli/x.py", "import sys\nsys.__loader__.load_module('posix')\n"),
    ("dynamic-imports", "rf/x.py", "import re\nre.__spec__.loader\n"),
    ("dynamic-imports", "cli/x.py", "breakpoint(cmd)\n"),
    ("dynamic-imports", "rf/x.py", "import types\ntypes.FunctionType(__loader__.source_to_code(b'x', 'y'), {})()\n"),
    ("dynamic-imports", "cli/x.py", "__spec__.loader\n"),
    ("dynamic-imports", "cli/x.py", "import sys\nhook = sys.breakpointhook\n"),
    ("dynamic-imports", "cli/x.py", "import sys\nsys.__breakpointhook__(cmd)\n"),
    (
        "shell-execution",
        "adapters/ssh/openssh.py",
        "loop._make_subprocess_transport(P, 'ls', True, None, None, None, 0)\n",
    ),
    ("shell-execution", "adapters/ssh/openssh.py", "from asyncio.unix_events import _UnixSubprocessTransport\n"),
    ("shell-execution", "cli/x.py", "from asyncio import base_subprocess\n"),
    ("shell-execution", "cli/x.py", "import asyncio.unix_events\n"),
    ("shell-execution", "cli/x.py", "import asyncio\nasyncio.base_subprocess.BaseSubprocessTransport\n"),
    ("shell-execution", "cli/x.py", "sh = loop.subprocess_shell\n"),
    ("shell-execution", "cli/x.py", "import functools\nfunctools.partial(loop.subprocess_shell, P)\n"),
    ("process-spawn-location", "cli/x.py", "ex = loop.subprocess_exec\n"),
    ("process-spawn-location", "cli/x.py", "sh = loop.subprocess_shell\n"),
    ("dynamic-imports", "cli/x.py", "len.__self__.exec(src)\n"),
    ("dynamic-imports", "cli/x.py", "import os\nos.getcwd.__self__.system('ls')\n"),
    ("dynamic-imports", "cli/x.py", "(i for i in ()).gi_frame.f_builtins['exec'](src)\n"),
    ("dynamic-imports", "cli/x.py", "frame.f_globals['x']\n"),
    ("dynamic-imports", "cli/x.py", "frame.f_locals['x']\n"),
    ("shell-execution", "rf/x.py", "run = exec\nrun(src)\n"),
    ("shell-execution", "cli/x.py", "e = eval\n"),
    ("shell-execution", "cli/x.py", "import os\nrun = os.system\n"),
    ("shell-execution", "cli/x.py", "import functools, os\nfunctools.partial(os.system, cmd)\n"),
    ("process-spawn-location", "cli/x.py", "import subprocess\n"),
    ("process-spawn-location", "cli/x.py", "import subprocess as sp\nsp.run(['ls'])\n"),
    ("process-spawn-location", "cli/x.py", "from subprocess import run\n"),
    ("process-spawn-location", "adapters/ssh/other.py", "import subprocess\n"),
    ("process-spawn-location", "cli/x.py", "import asyncio\nasyncio.create_subprocess_exec('ls')\n"),
    ("process-spawn-location", "cli/x.py", "from asyncio.subprocess import create_subprocess_shell\n"),
    ("process-spawn-location", "cli/x.py", "import asyncio\nasyncio.subprocess.create_subprocess_shell('ls')\n"),
    ("process-spawn-location", "cli/x.py", "import asyncio.subprocess as asp\nasp.create_subprocess_exec('ls')\n"),
    ("process-spawn-location", "cli/x.py", "from asyncio import create_subprocess_exec\n"),
    ("process-spawn-location", "cli/x.py", "from asyncio import subprocess\n"),
    ("process-spawn-location", "cli/x.py", "import asyncio\nasyncio.get_running_loop().subprocess_shell(P, 'ls')\n"),
    ("process-spawn-location", "cli/x.py", "loop.subprocess_exec(P, 'ls')\n"),
    ("process-spawn-location", "cli/x.py", "import os\npid = os.fork()\n"),
    ("process-spawn-location", "cli/x.py", "import multiprocessing\nmultiprocessing.Process(target=f).start()\n"),
    ("process-spawn-location", "cli/x.py", "from multiprocessing import Pool\n"),
    ("process-spawn-location", "cli/x.py", "from concurrent.futures import ProcessPoolExecutor\n"),
    ("process-spawn-location", "cli/x.py", "import concurrent.futures\nconcurrent.futures.ProcessPoolExecutor()\n"),
    ("process-spawn-location", "cli/x.py", "import pty\npty.fork()\n"),
    (
        "process-spawn-location",
        "cli/x.py",
        "from concurrent.futures.process import ProcessPoolExecutor\nProcessPoolExecutor()\n",
    ),
    ("process-spawn-location", "cli/x.py", "import concurrent.futures.process as cfp\ncfp.ProcessPoolExecutor()\n"),
    ("process-spawn-location", "cli/x.py", "from concurrent.futures import process\nprocess.ProcessPoolExecutor()\n"),
    ("process-spawn-location", "cli/x.py", "import concurrent.futures.process\n"),
    (
        "process-spawn-location",
        "cli/x.py",
        "import subprocess as sp\n\n\ndef a() -> None:\n    sp.run(['ls'])\n\n\n"
        "def b() -> None:\n    import math as sp\n    sp.sqrt(2)\n",
    ),
    ("shell-execution", "adapters/ssh/openssh.py", "import subprocess\nsubprocess.run('ls', shell=True)\n"),
    ("shell-execution", "adapters/ssh/openssh.py", "import subprocess\nsubprocess.run('ls', shell=flag)\n"),
    ("shell-execution", "adapters/ssh/openssh.py", "import subprocess\nsubprocess.run(['ls'], **opts)\n"),
    ("shell-execution", "adapters/ssh/openssh.py", "import subprocess as sp\nsp.Popen(['ls'], **{'shell': True})\n"),
    ("spawn-env-required", "adapters/ssh/openssh.py", "import subprocess\nsubprocess.run(['ssh', '-V'])\n"),
    ("spawn-env-required", "adapters/ssh/openssh.py", "import subprocess\nsubprocess.run(['ssh', '-V'], env=None)\n"),
    ("spawn-env-required", "adapters/ssh/hostkeys.py", "import subprocess as sp\nsp.Popen(['ssh'], **opts)\n"),
    ("spawn-env-required", "adapters/ssh/hostkeys.py", "from subprocess import check_output\ncheck_output(['ssh'])\n"),
    ("shell-execution", "cli/x.py", "import os\nos.system('ls')\n"),
    ("shell-execution", "cli/x.py", "from os import system\nsystem('ls')\n"),
    ("shell-execution", "cli/x.py", "import os as o\no.popen('ls')\n"),
    ("shell-execution", "cli/x.py", "import os\nos.execvp('ls', ['ls'])\n"),
    ("shell-execution", "cli/x.py", "import os\nos.posix_spawn('/bin/ls', ['ls'], {})\n"),
    ("shell-execution", "cli/x.py", "import pty\npty.spawn('sh')\n"),
    ("shell-execution", "cli/x.py", "import asyncio\nasyncio.create_subprocess_shell('ls')\n"),
    (
        "shell-execution",
        "adapters/ssh/openssh.py",
        "from asyncio.subprocess import create_subprocess_shell\ncreate_subprocess_shell('ls')\n",
    ),
    ("shell-execution", "adapters/ssh/openssh.py", "loop.subprocess_shell(P, 'ls')\n"),
    ("shell-execution", "adapters/ssh/openssh.py", "import subprocess\nsubprocess.run(('sh', '-c', cmd))\n"),
    ("shell-execution", "adapters/ssh/openssh.py", "import subprocess\nsubprocess.run(args=['/bin/zsh', '-c', cmd])\n"),
    (
        "shell-execution",
        "adapters/ssh/openssh.py",
        "import subprocess\nsubprocess.run(['/usr/bin/env', 'bash', '-c', cmd])\n",
    ),
    ("shell-execution", "adapters/ssh/openssh.py", "import subprocess\nsubprocess.run(['busybox', 'sh', '-c', cmd])\n"),
    ("shell-execution", "adapters/ssh/openssh.py", "import subprocess\nsubprocess.run(['bash', '-lc', cmd])\n"),
    ("shell-execution", "adapters/ssh/openssh.py", "import subprocess\nsubprocess.run(['sh', '-ec', cmd])\n"),
    (
        "shell-execution",
        "adapters/ssh/openssh.py",
        "import subprocess\nsubprocess.run(['/usr/bin/env', '-i', 'sh', '-c', cmd])\n",
    ),
    (
        "shell-execution",
        "adapters/ssh/openssh.py",
        "import subprocess\nsubprocess.run(['env', 'LC_ALL=C', 'bash', 'x.sh'])\n",
    ),
    ("shell-execution", "adapters/ssh/openssh.py", "import asyncio\nasyncio.create_subprocess_exec('sh', '-c', cmd)\n"),
    ("shell-execution", "adapters/ssh/openssh.py", "loop.subprocess_exec(P, 'sh', '-c', cmd)\n"),
    (
        "shell-execution",
        "adapters/ssh/openssh.py",
        "import asyncio\nasyncio.get_running_loop().subprocess_exec(P, 'sh', '-c', cmd)\n",
    ),
    (
        "shell-execution",
        "adapters/ssh/openssh.py",
        "import subprocess\nsubprocess.run(['env', '-u', 'X', 'sh', '-c', cmd])\n",
    ),
    (
        "shell-execution",
        "adapters/ssh/openssh.py",
        "import subprocess\nsubprocess.run(['/usr/bin/env', '-S', 'sh -c x'])\n",
    ),
    ("shell-execution", "adapters/ssh/openssh.py", "import subprocess\nsubprocess.run(['ash', '-c', cmd])\n"),
    ("shell-execution", "cli/x.py", "eval('1')\n"),
    ("shell-execution", "cli/x.py", "exec('x = 1')\n"),
    (
        "shell-execution",
        "adapters/ssh/openssh.py",
        "import subprocess as sp\n\n\ndef a() -> None:\n    sp.run(['sh', '-c', cmd])\n\n\n"
        "def b() -> None:\n    import math as sp\n    sp.sqrt(2)\n",
    ),
    ("shell-execution", "adapters/ssh/openssh.py", "import subprocess\nsubprocess.run(['sh', '-c', cmd])\n"),
    ("shell-execution", "adapters/ssh/openssh.py", "import subprocess\nsubprocess.Popen(['/bin/bash', '-c', cmd])\n"),
    ("shell-execution", "cli/x.py", "import asyncio\nasyncio.create_subprocess_exec('ls', **kw)\n"),
    ("json-parse-location", "cli/x.py", "import json\njson.loads(b'{}')\n"),
    ("json-parse-location", "cli/x.py", "from json import load\nload(f)\n"),
    ("json-parse-location", "cli/x.py", "import json as j\nj.loads('{}')\n"),
    ("json-parse-location", "cli/x.py", "import json\njson.JSONDecoder().decode('{}')\n"),
    ("json-parse-location", "adapters/unifi/parse.py", "import json\njson.loads(b'{}')\n"),
    ("json-parse-location", "cli/x.py", "import json\nlist(map(json.loads, lines))\n"),
    ("json-parse-location", "cli/x.py", "import functools, json\nparse = functools.partial(json.loads)\n"),
    ("json-parse-location", "cli/x.py", "from json.decoder import JSONDecoder\nJSONDecoder().decode(s)\n"),
    ("json-parse-location", "cli/x.py", "import json\njson.decoder.JSONDecoder()\n"),
    ("json-parse-location", "cli/x.py", "import json\njson.scanner.py_make_scanner(ctx)\n"),
    ("json-parse-location", "cli/x.py", "from json.decoder import scanstring\n"),
    ("json-parse-location", "cli/x.py", "import _json\n"),
    ("json-parse-location", "cli/x.py", "import json\nparse = getattr(json, 'loads')\nparse(b'{}')\n"),
    ("json-parse-location", "cli/x.py", "import json\nparse = vars(json)['loads']\n"),
    ("json-parse-location", "cli/x.py", "import json\nj = json\nj.loads('{}')\n"),
    ("json-parse-location", "cli/x.py", "import json\nparse = [json][0].loads\n"),
    ("json-parse-location", "cli/x.py", "import json as j\nrun(j)\n"),
    ("ssl-location", "cli/x.py", "import ssl\n"),
    ("ssl-location", "adapters/ssh/openssh.py", "from ssl import create_default_context\n"),
    ("ssl-location", "app/x.py", "import ssl as s\n"),
    ("ssl-location", "adapters/unifi/client.py", "import ssl\n"),
    ("ssl-location", "cli/x.py", "import _ssl\n"),
    ("tls-bypass-confinement", "cli/x.py", "import ssl\nctx.verify_mode = ssl.CERT_NONE\n"),
    ("tls-bypass-confinement", "cli/x.py", "from ssl import CERT_NONE\nctx.verify_mode = CERT_NONE\n"),
    ("tls-bypass-confinement", "cli/x.py", "import ssl\nmode = getattr(ssl, 'CERT_NONE')\n"),
    ("tls-bypass-confinement", "cli/x.py", "ctx.check_hostname = False\n"),
    ("tls-bypass-confinement", "cli/x.py", "ctx.check_hostname = 0\n"),
    ("tls-bypass-confinement", "cli/x.py", "ctx.check_hostname: bool = False\n"),
    ("tls-bypass-confinement", "cli/x.py", "setattr(ctx, 'check_hostname', False)\n"),
    ("tls-bypass-confinement", "cli/x.py", "import ssl\nctx.verify_mode = ssl.VerifyMode(0)\n"),
    ("tls-bypass-confinement", "cli/x.py", "import ssl\nctx = ssl._create_unverified_context()\n"),
    ("tls-bypass-confinement", "cli/x.py", "import ssl as s\nctx.verify_mode = s.CERT_NONE\n"),
    (
        "tls-bypass-confinement",
        "adapters/unifi/client.py",
        "import ssl\nssl.create_default_context(ssl.Purpose.CLIENT_AUTH)\n",
    ),
    ("tls-bypass-confinement", "adapters/unifi/client.py", "import ssl\nssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)\n"),
    ("tls-bypass-confinement", "adapters/unifi/client.py", "import ssl\nssl.SSLContext(ssl.PROTOCOL_TLS)\n"),
    ("tls-bypass-confinement", "adapters/unifi/client.py", "import ssl\nssl._create_stdlib_context()\n"),
    ("tls-bypass-confinement", "adapters/unifi/client.py", "from ssl import Purpose\nmake(Purpose.CLIENT_AUTH)\n"),
    ("tls-bypass-confinement", "adapters/unifi/tls.py", "import ssl\nctx = ssl.SSLContext()\n"),
    ("tls-bypass-confinement", "adapters/unifi/tls.py", "import ssl\nctx = ssl.SSLContext(2)\n"),
    (
        "tls-bypass-confinement",
        "adapters/unifi/tls.py",
        "import ssl\nctx = ssl.SSLContext(protocol=ssl.PROTOCOL_TLS)\n",
    ),
    ("tls-bypass-confinement", "adapters/unifi/tls.py", "import ssl\ngetattr(ssl, '_create_stdlib_context')()\n"),
    ("tls-bypass-confinement", "adapters/unifi/tls.py", "import ssl\ngetattr(ssl, 'PROTOCOL_TLS_SERVER')\n"),
    ("tls-bypass-confinement", "adapters/unifi/tls.py", "import ssl\npem = ssl.get_server_certificate((host, 443))\n"),
    ("tls-bypass-confinement", "adapters/unifi/tls.py", "import ssl\ns = ssl.wrap_socket(sock)\n"),
    (
        "tls-bypass-confinement",
        "adapters/unifi/tls.py",
        "import ssl\n\n\nclass PinnedHTTPSConnection:\n"
        "    def connect(self) -> None:\n        self.ctx.verify_mode = ssl.CERT_NONE\n",
    ),
    (
        "tls-bypass-confinement",
        "adapters/unifi/client.py",
        "import ssl\n\n\nclass PinnedHTTPSConnection:\n"
        "    def __init__(self) -> None:\n        self.ctx.verify_mode = ssl.CERT_NONE\n",
    ),
]


@pytest.mark.parametrize(("checker_name", "relpath", "snippet"), BAD_SNIPPETS)
def test_checker_rejects_known_bad_snippet(checker_name: str, relpath: str, snippet: str) -> None:
    assert CHECKERS[checker_name](ast.parse(snippet), relpath) != []


GOOD_SNIPPETS: list[tuple[str, str, str]] = [
    (
        "spawn-env-required",
        "adapters/ssh/openssh.py",
        "import subprocess\nsubprocess.run(['ssh', '-V'], env=dict(e))\n",
    ),
    ("spawn-env-required", "adapters/ssh/openssh.py", "import subprocess\nsubprocess.CompletedProcess(['ssh'], 0)\n"),
    ("spawn-env-required", "cli/x.py", "import subprocess\nsubprocess.run(['ls'])\n"),
    (
        "core-imports",
        "rf/x.py",
        "import math\nfrom dataclasses import dataclass\nfrom unifiwifioptimizer.domain import models\n",
    ),
    ("core-imports", "domain/x.py", "from . import errors\nfrom .errors import UwoError\nfrom .models import Band\n"),
    ("core-imports", "cli/x.py", "import subprocess\n"),
    ("process-spawn-location", "adapters/ssh/openssh.py", "import subprocess\nsubprocess.run(['ssh'], shell=False)\n"),
    ("shell-execution", "adapters/ssh/openssh.py", "import subprocess\nsubprocess.run(['ssh'], check=True)\n"),
    ("json-parse-location", "adapters/unifi/client.py", "import json\njson.loads(b'{}')\n"),
    ("json-parse-location", "cli/x.py", "import json\njson.dumps({})\n"),
    ("ssl-location", "adapters/unifi/tls.py", "import ssl\n"),
    (
        "ssl-location",
        "adapters/unifi/client.py",
        "import http.client\nfrom unifiwifioptimizer.adapters.unifi import tls\n",
    ),
    (
        "json-parse-location",
        "cli/x.py",
        "import json\n\n\ndef dump(v: object) -> str:\n    return json.dumps(v, sort_keys=True)\n",
    ),
    ("process-spawn-location", "cli/x.py", "import asyncio\nasyncio.run(main())\n"),
    (
        "process-spawn-location",
        "cli/x.py",
        "from concurrent.futures import ThreadPoolExecutor\nThreadPoolExecutor(max_workers=4)\n",
    ),
    ("process-spawn-location", "cli/x.py", "import os\nos.getpid()\n"),
    ("process-spawn-location", "cli/x.py", "from concurrent.futures.thread import ThreadPoolExecutor\n"),
    (
        "json-parse-location",
        "adapters/ssh/hostkeys.py",
        "import hashlib\nimport json\n\n\ndef alias(origin: str, site: str, mac: str) -> str:\n"
        "    canonical = json.dumps([origin, site, mac], sort_keys=True, separators=(',', ':'))\n"
        "    return 'uwo-' + hashlib.sha256(canonical.encode()).hexdigest()[:32]\n",
    ),
    (
        "json-parse-location",
        "adapters/ssh/hostkeys.py",
        "import hashlib\nimport json\nh = hashlib.sha256(json.dumps([o, s, m], sort_keys=True).encode()).hexdigest()\n",
    ),
    ("json-parse-location", "adapters/unifi/dump.py", "import json\np.write_bytes(json.dumps(d).encode('utf-8'))\n"),
    ("json-parse-location", "cli/x.py", "def f(json: str) -> str:\n    return json\n"),
    (
        "dynamic-imports",
        "cli/x.py",
        "from importlib import resources\nfrom importlib.metadata import version\nresources.files(p)\n",
    ),
    ("dynamic-imports", "cli/x.py", "import sys\nprint(sys.argv, file=sys.stderr)\n"),
    ("dynamic-imports", "cli/x.py", "import importlib.metadata\nimportlib.metadata.version('x')\n"),
    ("dynamic-imports", "cli/x.py", "from importlib import metadata, resources\nmetadata.version('x')\n"),
    ("dynamic-imports", "cli/x.py", "from importlib.resources import files\nfiles(p)\n"),
    ("dynamic-imports", "cli/x.py", "from importlib.resources import as_file, files\nas_file(files(p))\n"),
    ("dynamic-imports", "cli/x.py", "import importlib.resources\nimportlib.resources.files(p)\n"),
    ("shell-execution", "cli/x.py", "import os\nos.getcwd()\nos.environ.get('A')\n"),
    ("star-imports", "cli/x.py", "from os import getcwd\nfrom . import util\n"),
    ("dynamic-imports", "cli/x.py", "x = 'breakpoint in prose'\n# breakpoint() is not called here\n"),
    (
        "shell-execution",
        "adapters/ssh/openssh.py",
        "from asyncio import TimeoutError\nawait loop.subprocess_exec(P, 'ssh', 'h')\n",
    ),
    ("process-spawn-location", "adapters/ssh/openssh.py", "import asyncio\nloop.subprocess_exec(P, 'ssh')\n"),
    ("shell-execution", "cli/x.py", "import asyncio\nasyncio.run(main())\n"),
    ("dynamic-imports", "cli/x.py", "# __globals__ is not touched here\nx = 'about __globals__ in prose'\n"),
    ("json-parse-location", "report/json.py", "import json\ntext = json.JSONEncoder(indent=2).encode(x)\n"),
    (
        "json-parse-location",
        "adapters/unifi/parse.py",
        "import json\ntry:\n    pass\nexcept json.JSONDecodeError:\n    pass\n",
    ),
    (
        "shell-execution",
        "adapters/ssh/openssh.py",
        "import subprocess\nsubprocess.run(['ssh-keyscan', '-T', '5', ip])\n",
    ),
    (
        "shell-execution",
        "adapters/ssh/openssh.py",
        "import subprocess\nsubprocess.run(['ssh', '-T', host, 'sh', '-s'])\n",
    ),
    (
        "core-imports",
        "analysis/x.py",
        "from unifiwifioptimizer.rf import corridor\nfrom unifiwifioptimizer import domain\n",
    ),
    ("core-imports", "analysis/x.py", "from unifiwifioptimizer.compliance.engine import evaluate_site\n"),
    ("core-imports", "rf/x.py", "from unifiwifioptimizer.domain.analysis import RoamingCap\n"),
    ("core-imports", "domain/report.py", "from unifiwifioptimizer.domain.models import Band\n"),
    ("layer-imports", "report/x.py", "from unifiwifioptimizer.app.use_cases import SiteOverview\n"),
    ("layer-imports", "app/x.py", "from unifiwifioptimizer.adapters.unifi.client import UnifiClient\n"),
    (
        "tls-bypass-confinement",
        "adapters/unifi/tls.py",
        "import hashlib\nimport hmac\nimport http.client\nimport ssl\n\n\n"
        "class PinnedHTTPSConnection(http.client.HTTPSConnection):\n"
        "    def __init__(self, host: str, pin: bytes) -> None:\n"
        "        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)\n"
        "        ctx.minimum_version = ssl.TLSVersion.TLSv1_2\n"
        "        ctx.check_hostname = False\n        ctx.verify_mode = ssl.CERT_NONE\n"
        "        super().__init__(host, context=ctx)\n        self._pin = pin\n\n"
        "    def connect(self) -> None:\n        super().connect()\n"
        "        der = self.sock.getpeercert(binary_form=True)\n"
        "        if not hmac.compare_digest(hashlib.sha256(der).digest(), self._pin):\n"
        "            self.close()\n            raise TlsPinMismatchError()\n",
    ),
    (
        "tls-bypass-confinement",
        "adapters/unifi/tls.py",
        "import ssl\n\n\ndef system_ca() -> ssl.SSLContext:\n    return ssl.create_default_context()\n",
    ),
    (
        "tls-bypass-confinement",
        "adapters/unifi/tls.py",
        "import ssl\n\n\ndef custom_ca(ca_cert: str) -> ssl.SSLContext:\n"
        "    return ssl.create_default_context(cafile=ca_cert)\n",
    ),
    (
        "tls-bypass-confinement",
        "adapters/unifi/tls.py",
        "import ssl\nctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)\nctx.minimum_version = ssl.TLSVersion.TLSv1_2\n",
    ),
]


@pytest.mark.parametrize(("checker_name", "relpath", "snippet"), GOOD_SNIPPETS)
def test_checker_accepts_known_good_snippet(checker_name: str, relpath: str, snippet: str) -> None:
    assert CHECKERS[checker_name](ast.parse(snippet), relpath) == []
