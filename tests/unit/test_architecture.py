"""Structural gates over the package source.

Each rule guards a boundary the design depends on: a pure core without I/O, one place that spawns
processes, one place that parses controller JSON, one place that is allowed to disable certificate
verification. The rules are checked on the AST with import aliases resolved, so a violation fails here
before a reviewer sees it. The checkers are also run against a table of known-bad snippets, which keeps
the gate logic itself under test.
"""

import ast
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest

import unifiwifioptimizer

PACKAGE_ROOT = Path(unifiwifioptimizer.__file__).parent
PACKAGE = "unifiwifioptimizer"

CORE_PACKAGES = frozenset({"domain", "rf", "compliance", "analysis", "ports"})
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

DYNAMIC_IMPORTS = frozenset({"__import__", "builtins.__import__", "importlib.import_module", "importlib.__import__"})
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
    if layer_of(relpath) not in CORE_PACKAGES:
        return []
    found: list[str] = []
    for module, names in imported_modules(tree, relpath):
        root = module.split(".")[0]
        if root == PACKAGE:
            layers = [module.split(".")[1]] if "." in module else names
            if not layers:
                found.append(f"imports the bare {PACKAGE} package")
            found.extend(
                f"imports {PACKAGE}.{layer}, which is not a core package"
                for layer in layers
                if layer not in CORE_PACKAGES
            )
        elif root not in CORE_ALLOWED_STDLIB:
            found.append(f"imports {module}, which is not on the core allowlist")
    return found


def check_dynamic_imports(tree: ast.Module, relpath: str) -> list[str]:
    aliases = aliases_of(tree, relpath)
    return [f"dynamic import via {name}" for _, names in calls(tree, aliases) for name in names & DYNAMIC_IMPORTS]


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
    for call, names in calls(tree, aliases):
        found.extend(f"calls {n}" for n in names if n.startswith(PROCESS_SPAWN_PREFIXES) or n in PROCESS_CREATION_NAMES)
        if isinstance(call.func, ast.Attribute) and call.func.attr in LOOP_SPAWN_ATTRIBUTES:
            found.append(f"calls .{call.func.attr}()")
    for node in ast.walk(tree):
        if isinstance(node, ast.Name | ast.Attribute):
            found.extend(f"references {n}" for n in qualified_names(node, aliases) & PROCESS_CREATION_NAMES)
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
    found: list[str] = []
    for call, names in calls(tree, aliases):
        label = "/".join(sorted(names)) or "<call>"
        found.extend(f"calls {n}" for n in names if n in SHELL_CALLS or n.startswith(SHELL_CALL_PREFIXES))
        if isinstance(call.func, ast.Attribute) and call.func.attr == "subprocess_shell":
            found.append("calls .subprocess_shell()")
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


CHECKERS: dict[str, Checker] = {
    "core-imports": check_core_imports,
    "dynamic-imports": check_dynamic_imports,
    "process-spawn-location": check_process_spawn_location,
    "shell-execution": check_shell_execution,
    "json-parse-location": check_json_parse_location,
    "ssl-location": check_ssl_location,
    "tls-bypass-confinement": check_tls_bypass_confinement,
}


def test_the_core_has_source_files() -> None:
    assert any(layer_of(relative(p)) in CORE_PACKAGES for p in source_files())


@pytest.mark.parametrize("path", source_files(), ids=relative)
@pytest.mark.parametrize("checker", CHECKERS.values(), ids=list(CHECKERS))
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
    ("dynamic-imports", "cli/x.py", "import importlib\nimportlib.import_module('subprocess')\n"),
    ("dynamic-imports", "cli/x.py", "__import__('subprocess')\n"),
    ("dynamic-imports", "cli/x.py", "from importlib import import_module as im\nim('os')\n"),
    ("dynamic-imports", "cli/x.py", "from builtins import __import__ as imp\nimp('subprocess')\n"),
    ("dynamic-imports", "cli/x.py", "import builtins\nbuiltins.__import__('subprocess')\n"),
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
        "core-imports",
        "rf/x.py",
        "import math\nfrom dataclasses import dataclass\nfrom unifiwifioptimizer.domain import models\n",
    ),
    ("core-imports", "domain/x.py", "from . import errors\nfrom .errors import UwoError\nfrom ..rf import corridor\n"),
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
