"""Inventory gate over the security tests: every topic T1-T19 has a test that claims it, and every claim
names a topic.

The claim is the `security` marker on the test itself (`@pytest.mark.security("T3")`), read from the AST of
every module under tests/ rather than from pytest's collection, so the integration tier counts without
Docker. The grammar is fixed on purpose: a marker in a position pytest would honour but this gate does not
understand would count for nothing, so every other shape fails here with its location. Two layers make that
hold. Statically, every spelling of the mark generator (`<x>.mark`, a name bound to it) must sit in a
position the gate reads — a dotted decorator, a `pytestmark` element, a `pytest.param(marks=...)`, or a
plain alias binding — the `pytest` module itself may only be the base of a plain attribute access, pytest's
internals are not imported, markers are never added at run time (`add_marker`, `applymarker`), which no
source reader could see, and a claim in a file pytest would never collect (not `test_*.py`/`*_test.py`) is
rejected. At collection time, tests/conftest.py compares pytest's own markers on every collected item with
the claims read here (`collection_mismatches`), in both directions and again at the end of the session over the
tests that ran and
the deselected items; a test no case of which ran may not carry it; the `integration` marker must agree with
the test's directory (a marked test outside the tree runs in no `./dev ci` run, an unmarked test inside it
would run without the harness); every claim in
a module pytest started collecting must be carried by such a test (a module that skips itself at import
time, a class or function that opts out, a hook that drops the test, all leave a dead claim); and in a run
over the whole tree every module holding a claim must have started. So for every test pytest collects, its
security markers are exactly the claims counted here, whatever the spelling, and no counted claim survives
without a test pytest would run. The session-end comparison in tests/conftest.py judges what actually ran,
with the markers carried at run time, so a run-time skip, an xfail, an intercepted test protocol or a hook
that mutates the item set after collection leave a dead or a mismatched claim as well. Grammar this gate
does not read and that therefore fails closed at collection: a nested test class (rejected here) and a test
method inherited from a base class (pytest sees the base's markers, the gate reads the subclass only).
What the session-end comparison proves is that pytest ran the call phase of a test carrying the marker,
not what the body did. Trust boundary: the tests, conftests and plugins of this repository are trusted
code; a hook or fixture that replaces a test body, forges test reports or resets `session.exitstatus` after
the gate's own is outside its model, as is a test deselected for good by a `--deselect`/`-k` in the addopts
or by a hook that reports its own deselection (indistinguishable from a tier choice).
"""

import ast
from collections import Counter
from collections.abc import Collection, Sequence
from dataclasses import dataclass
from pathlib import Path

import pytest

TESTS_DIR = Path(__file__).resolve().parents[1]

SECURITY_TOPICS: dict[str, str] = {
    "T1": "TLS default mode: system roots verify the chain and the hostname, a self-signed certificate is rejected",
    "T2": "TLS custom CA mode: chain and hostname checked, a certificate that does not name the host is rejected",
    "T3": "TLS pin mode: the SHA-256 pin is compared before the first request byte, a mismatch closes the socket",
    "T4": "no redirect is followed; every 3xx status is an error",
    "T5": "response caps: declared length, streamed body, Content-Encoding, JSON depth and item counts",
    "T6": "an unknown host key alias ends the call before any authentication or process start",
    "T7": "a host-key mismatch is classified as HostKeyMismatchError, never retried",
    "T8": (
        "trust only via trust-host-keys: pin precedence over the controller fingerprint, --yes vs "
        "--accept-unverified, the scan never adds a key"
    ),
    "T9": "the SSH password never reaches argv, logs, exceptions or other children; only SSH_ASKPASS in password mode",
    "T10": "redaction on the real CLI --dump-api path",
    "T11": "Secret rendering is masked everywhere; the report JSON refuses a secret",
    "T12": "every external string is sanitised before terminal output",
    "T13": (
        "configuration file permissions, owner, symlink, FIFO and check-then-read races; init writes 0600 with O_EXCL"
    ),
    "T14": "known_hosts store permissions, owner, symlinks and the atomic locked write",
    "T15": "access-point address gate: private, link-local and ULA only, public only by explicit opt-in",
    "T16": "ssh argv hardening: pinned options, absolute quoted percent-escaped paths, refused characters",
    "T17": "OpenSSH 8.4 floor in the harness: a file named none changes nothing, askpass works on 8.4",
    "T18": (
        "remote script: valid busybox ash, toggle only with the flag, traps restore the interface, caps kill the "
        "process group"
    ),
    "T19": "environment: an OpenSSH client below 8.4 or a missing ssh/ssh-keyscan ends the run with exit 7",
}


@dataclass(frozen=True)
class Claim:
    topic: str
    location: str


@dataclass(frozen=True)
class Violation:
    location: str
    reason: str


def _is_security_mark(node: ast.expr) -> bool:
    """`pytest.mark.security` spelled exactly so; an alias is a violation found by the free scan."""
    return (
        isinstance(node, ast.Attribute)
        and node.attr == "security"
        and isinstance(node.value, ast.Attribute)
        and node.value.attr == "mark"
        and isinstance(node.value.value, ast.Name)
        and node.value.value.id == "pytest"
    )


def _mark_aliases(module: ast.Module, placed: set[int]) -> set[str]:
    """Names that denote `pytest.mark` anywhere in the module: `from pytest import mark [as x]`, a plain or
    annotated assignment from a chain ending in `.mark`, a tuple assignment, and an alias of an alias —
    found to a fixed point so that chains of aliases are covered. The generator reference on the right-hand
    side of each such binding is recorded as accepted; any other way of binding it is left for the free scan."""
    names: set[str] = set()
    for node in ast.walk(module):
        if isinstance(node, ast.ImportFrom) and node.module == "pytest":
            names.update(alias.asname or alias.name for alias in node.names if alias.name == "mark")

    def denotes_mark(value: ast.expr) -> bool:
        return (isinstance(value, ast.Attribute) and value.attr == "mark") or (
            isinstance(value, ast.Name) and value.id in names
        )

    changed = True
    while changed:
        changed = False
        for node in ast.walk(module):
            pairs: list[tuple[ast.expr, ast.expr]] = []
            if isinstance(node, ast.AnnAssign) and node.value is not None:
                pairs.append((node.target, node.value))
            elif isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Tuple) and isinstance(node.value, ast.Tuple):
                        pairs.extend(zip(target.elts, node.value.elts, strict=False))
                    else:
                        pairs.append((target, node.value))
            for target, value in pairs:
                if isinstance(target, ast.Name) and denotes_mark(value):
                    placed.add(id(value))
                    if target.id not in names:
                        names.add(target.id)
                        changed = True
    return names


def _module_aliases(module: ast.Module) -> set[str]:
    """Names bound to the pytest module itself (`import pytest [as x]`)."""
    names: set[str] = set()
    for node in ast.walk(module):
        if isinstance(node, ast.Import):
            names.update(alias.asname or alias.name for alias in node.names if alias.name == "pytest")
    return names


def _is_generator(node: ast.AST, aliases: set[str]) -> bool:
    """A spelling of the mark generator: `<anything>.mark` or a read of a name bound to it."""
    return (isinstance(node, ast.Attribute) and node.attr == "mark") or (
        isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load) and node.id in aliases
    )


def _dotted_chain(expr: ast.expr) -> list[ast.expr] | None:
    """The nodes of `a.b.c` or `a.b.c(...)` from the outside in, ending in the name; None for any other
    shape (a call of a call, a subscript, a `getattr`, a walrus), which is the shape pytest would still
    honour but this gate cannot read."""
    if isinstance(expr, ast.Call):
        expr = expr.func
    chain: list[ast.expr] = []
    while isinstance(expr, ast.Attribute):
        chain.append(expr)
        expr = expr.value
    if not isinstance(expr, ast.Name):
        return None
    chain.append(expr)
    return chain


def _is_pytest_param(call: ast.Call, module_names: set[str]) -> bool:
    chain = _dotted_chain(call)
    return (
        chain is not None
        and len(chain) == 2
        and isinstance(chain[0], ast.Attribute)
        and chain[0].attr == "param"
        and isinstance(chain[1], ast.Name)
        and chain[1].id in module_names
    )


def _place_mark_positions(
    module: ast.Module, relpath: str, aliases: set[str], module_names: set[str], placed: set[int]
) -> list[Violation]:
    """Record the generator references that sit where pytest reads a mark: a decorator on any function or
    class, a `pytestmark` element, the `marks=` of `pytest.param(...)`. A decorator or `pytestmark` element
    of any other shape is a violation, whatever it decorates: the gate must be able to read every mark."""
    violations: list[Violation] = []

    def place(expr: ast.expr, what: str) -> None:
        chain = _dotted_chain(expr)
        if chain is None:
            violations.append(Violation(f"{relpath}:{expr.lineno}", f"{what} of a shape this gate cannot read"))
            return
        placed.update(id(node) for node in chain if _is_generator(node, aliases))

    for node in ast.walk(module):
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            for decorator in node.decorator_list:
                place(decorator, "a decorator")
        elif isinstance(node, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == "pytestmark" for t in node.targets
        ):
            elements = node.value.elts if isinstance(node.value, ast.List | ast.Tuple) else [node.value]
            for element in elements:
                place(element, "a pytestmark element")
        elif isinstance(node, ast.Call) and _is_pytest_param(node, module_names):
            for keyword in node.keywords:
                if keyword.arg != "marks":
                    continue
                marks = keyword.value.elts if isinstance(keyword.value, ast.List | ast.Tuple) else [keyword.value]
                for mark in marks:
                    place(mark, "a pytest.param mark")
    return violations


def _imports_pytest_internals(node: ast.AST) -> bool:
    def internal(module_name: str) -> bool:
        return module_name == "_pytest" or module_name.startswith("_pytest.")

    if isinstance(node, ast.Import):
        return any(internal(alias.name) for alias in node.names)
    return isinstance(node, ast.ImportFrom) and node.module is not None and internal(node.module)


def _adds_a_marker_at_run_time(node: ast.AST) -> bool:
    """`item.add_marker(...)` / `request.applymarker(...)`: pytest honours these after collection, so no
    reader of the source — this gate or the collection-time cross-check — can see them."""
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in {"add_marker", "applymarker"}
    )


def _star_imports_pytest(node: ast.AST) -> bool:
    return isinstance(node, ast.ImportFrom) and node.module == "pytest" and any(a.name == "*" for a in node.names)


def _is_test_module(relpath: str) -> bool:
    """pytest's default `python_files`: the only modules whose tests run at all."""
    name = relpath.rsplit("/", 1)[-1]
    return name.startswith("test_") or name.endswith("_test.py")


def _free_references(
    module: ast.Module, relpath: str, aliases: set[str], module_names: set[str], placed: set[int]
) -> list[Violation]:
    """Every remaining spelling of the mark generator, every use of the pytest module other than as the base
    of a plain attribute, and every import of pytest's internals — each a way to build a marker the gate
    would not see."""
    violations: list[Violation] = []
    attribute_bases = {
        id(node.value)
        for node in ast.walk(module)
        if isinstance(node, ast.Attribute) and not node.attr.startswith("__")
    }
    for node in ast.walk(module):
        where = f"{relpath}:{getattr(node, 'lineno', 0)}"
        if _is_generator(node, aliases) and id(node) not in placed:
            violations.append(Violation(where, "pytest.mark referenced outside a position this gate reads"))
        elif isinstance(node, ast.Name) and node.id in module_names and id(node) not in attribute_bases:
            violations.append(Violation(where, "the pytest module used as a value, not as `pytest.<name>`"))
        elif _imports_pytest_internals(node):
            violations.append(Violation(where, "pytest internals imported"))
        elif _star_imports_pytest(node):
            violations.append(Violation(where, "star import from pytest"))
        elif _adds_a_marker_at_run_time(node):
            violations.append(Violation(where, "a marker added at run time"))
    return violations


def _looks_like_a_mark(value: ast.expr, aliases: set[str]) -> bool:
    """`<anything>.mark.security`, `mark.security` or `<alias of pytest.mark>.security`: a mark reached
    otherwise than through `pytest.mark`. An unrelated attribute named `security` (a model field) has
    neither `mark` nor such an alias in front of it."""
    if isinstance(value, ast.Attribute):
        return value.attr == "mark"
    return isinstance(value, ast.Name) and value.id in aliases


def _topics_of(call: ast.Call, location: str) -> tuple[list[str], list[Violation]]:
    topics: list[str] = []
    violations: list[Violation] = []
    if call.keywords or not call.args:
        violations.append(Violation(location, "security(...) takes one or more positional topic ids"))
    for argument in call.args:
        if isinstance(argument, ast.Constant) and isinstance(argument.value, str):
            topics.append(argument.value)
        else:
            violations.append(Violation(location, "a topic id must be a string literal"))
    return topics, violations


def _decorator_claims(
    decorators: list[ast.expr], location: str, accepted: set[int]
) -> tuple[list[Claim], list[Violation]]:
    claims: list[Claim] = []
    violations: list[Violation] = []
    marks = {d.func.attr for d in decorators if isinstance(d, ast.Call) and isinstance(d.func, ast.Attribute)}
    marks |= {d.attr for d in decorators if isinstance(d, ast.Attribute)}
    for decorator in decorators:
        if not (isinstance(decorator, ast.Call) and _is_security_mark(decorator.func)):
            continue
        accepted.add(id(decorator))
        accepted.add(id(decorator.func))
        topics, found = _topics_of(decorator, location)
        violations.extend(found)
        if marks & {"skip", "skipif", "xfail"}:
            violations.append(Violation(location, "a skipped or xfail test proves no security topic"))
        claims.extend(Claim(topic, location) for topic in topics)
    return claims, violations


def _pytestmark_claims(module: ast.Module, relpath: str, accepted: set[int]) -> tuple[list[Claim], list[Violation]]:
    claims: list[Claim] = []
    violations: list[Violation] = []
    bindings = [
        node
        for node in module.body
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "pytestmark" for t in node.targets)
    ]
    if len(bindings) > 1:
        violations.append(Violation(relpath, "pytestmark is bound more than once; pytest keeps only the last"))
    for binding in bindings:
        marks = binding.value.elts if isinstance(binding.value, ast.List | ast.Tuple) else [binding.value]
        for mark in marks:
            if isinstance(mark, ast.Call) and _is_security_mark(mark.func):
                accepted.add(id(mark))
                accepted.add(id(mark.func))
                topics, found = _topics_of(mark, f"{relpath}::pytestmark")
                violations.extend(found)
                claims.extend(Claim(topic, f"{relpath}::pytestmark") for topic in topics)
    return claims, violations


def scan_module(module: ast.Module, relpath: str) -> tuple[list[Claim], list[Violation]]:
    """Claims in the positions pytest collects; every other `mark.security` in the module, and every spelling
    of the mark generator outside a position this gate reads, is a violation."""
    claims: list[Claim] = []
    violations: list[Violation] = []
    accepted: set[int] = set()
    placed: set[int] = set()
    module_names = _module_aliases(module)
    aliases = _mark_aliases(module, placed)
    violations += _place_mark_positions(module, relpath, aliases, module_names, placed)
    violations += _free_references(module, relpath, aliases, module_names, placed)
    found, bad = _pytestmark_claims(module, relpath, accepted)
    claims += found
    violations += bad
    for node in module.body:
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and node.name.startswith("test_"):
            found, bad = _decorator_claims(node.decorator_list, f"{relpath}::{node.name}", accepted)
            claims += found
            violations += bad
        elif isinstance(node, ast.ClassDef) and node.name.startswith("Test"):
            found, bad = _decorator_claims(node.decorator_list, f"{relpath}::{node.name}", accepted)
            claims += found
            violations += bad
            for member in node.body:
                if isinstance(member, ast.ClassDef) and member.name.startswith("Test"):
                    violations.append(
                        Violation(
                            f"{relpath}::{node.name}::{member.name}", "a nested test class is not read; flatten it"
                        )
                    )
                if isinstance(member, ast.FunctionDef | ast.AsyncFunctionDef) and member.name.startswith("test_"):
                    found, bad = _decorator_claims(
                        member.decorator_list, f"{relpath}::{node.name}::{member.name}", accepted
                    )
                    claims += found
                    violations += bad
    if claims and not _is_test_module(relpath):
        # Such a module never starts collection, so not even the dead-claim pass would see these claims.
        violations.append(Violation(relpath, "a claim in a module pytest never collects"))
    called = {id(node.func) for node in ast.walk(module) if isinstance(node, ast.Call)}
    for any_node in ast.walk(module):
        if not isinstance(any_node, ast.Attribute) or any_node.attr != "security" or id(any_node) in accepted:
            continue
        where = f"{relpath}:{any_node.lineno}"
        if _is_security_mark(any_node):
            reason = "in a position pytest does not collect" if id(any_node) in called else "bound to a name"
            violations.append(Violation(where, f"security marker {reason}"))
        elif _looks_like_a_mark(any_node.value, aliases):
            violations.append(Violation(where, "security marker behind an alias, or not pytest.mark.security"))
    return claims, violations


def module_paths(root: Path = TESTS_DIR) -> list[Path]:
    return sorted(p for p in root.rglob("*.py") if "__pycache__" not in p.parts)


def inventory(root: Path = TESTS_DIR) -> tuple[list[Claim], list[Violation]]:
    claims: list[Claim] = []
    violations: list[Violation] = []
    for path in module_paths(root):
        relpath = path.relative_to(root).as_posix()
        found, bad = scan_module(ast.parse(path.read_text(encoding="utf-8")), relpath)
        claims += found
        violations += bad
    return claims, violations


@dataclass(frozen=True)
class CollectedItem:
    """pytest's view of one collected test: where it is and which `security` topics its markers carry."""

    relpath: str
    class_qualname: str | None
    function_name: str
    topics: tuple[str, ...]
    # A `security` marker without positional topics, or with keywords, names no topic: pytest still selects
    # the test under `-m security`, so it must be reported rather than compared as "no topics".
    malformed_markers: int = 0
    # Only a test function has a location the gate reads; a marker on any other kind of item is reported.
    is_function: bool = True
    # Skipped in setup or call, or xfail: nothing ran that proves a topic. When every case of a test
    # function ended so, its claim is reported.
    skipped: bool = False
    # Deselected by the run's own `-m`/`-k`: not run here, but not dead either (a tier choice).
    deselected: bool = False
    # The `integration` marker decides the tier a test runs in; it must agree with the test's directory.
    integration: bool = False

    @property
    def locations(self) -> tuple[str, ...]:
        """The claim locations that apply to this item, module first: pytest layers markers the same way."""
        module = f"{self.relpath}::pytestmark"
        if self.class_qualname is None:
            return (module, f"{self.relpath}::{self.function_name}")
        cls = f"{self.relpath}::{self.class_qualname.replace('.', '::')}"
        return (module, cls, f"{cls}::{self.function_name}")


def collection_mismatches(
    collected: Sequence[CollectedItem],
    claims: Sequence[Claim],
    started_modules: Collection[str] | None,
    require_started: bool = False,
) -> list[str]:
    """Where pytest's view and the gate's reading differ: an item whose markers carry topics the gate did not
    read at its locations, or the other way round, or that pytest will always skip; and, given the modules
    pytest started collecting, a claim in one of them that no item carries — a marker on something pytest
    does not run proves nothing, whether the module skipped itself at import time, the class or function
    opted out, or a hook dropped the test. `None` skips that direction for runs that collect part of a module
    on purpose. With `require_started` (a run over the whole tree) a claim in a module pytest never started is
    reported too, which leaves no way to hold a claim outside pytest's reach."""
    by_location: dict[str, list[str]] = {}
    for claim in claims:
        by_location.setdefault(claim.location, []).append(claim.topic)
    problems: list[str] = []
    matched: set[str] = set()
    runs_nothing: dict[str, bool] = {}
    for item in collected:
        where = item.locations[-1]
        expected = [topic for location in item.locations for topic in by_location.get(location, [])]
        matched.update(item.locations)
        if item.integration != item.relpath.startswith("integration/"):
            consequence = (
                "no ./dev ci run executes this test"
                if item.integration
                else "the unit tiers would run it without the harness"
            )
            placement = "integration marker outside" if item.integration else "no integration marker under"
            problems.append(f"{where}: {placement} tests/integration/ — {consequence}")
        if not item.is_function:
            if item.topics or item.malformed_markers:
                problems.append(f"{where}: a security marker on an item that is not a test function")
            continue
        if item.malformed_markers:
            problems.append(f"{where}: a security marker without topic ids or with keywords")
        elif Counter(expected) != Counter(item.topics):
            problems.append(f"{where}: pytest sees security{tuple(item.topics)}, the gate read {tuple(expected)}")
        elif item.topics and not item.deselected:
            runs_nothing[where] = runs_nothing.get(where, True) and item.skipped
    problems += [
        f"{where}: a security marker on a test no case of which ran (skipped or xfail)"
        for where, nothing_runs in runs_nothing.items()
        if nothing_runs
    ]
    if started_modules is not None:
        for location in sorted(by_location.keys() - matched):
            module = location.split("::", 1)[0]
            if module in started_modules:
                problems.append(f"{location}: the gate read a claim here, but no test under it ran")
            elif require_started:
                problems.append(f"{location}: the gate read a claim here, but pytest never started this module")
    return problems


def test_the_scan_reaches_every_module_under_tests_including_conftests() -> None:
    names = {p.relative_to(TESTS_DIR).as_posix() for p in module_paths()}
    assert "integration/harness/conftest.py" in names and "unit/test_security_inventory.py" in names


def test_no_marker_sits_where_the_gate_cannot_read_it() -> None:
    _, violations = inventory()
    assert violations == []


def test_every_topic_is_claimed_by_at_least_one_test() -> None:
    claims, _ = inventory()
    claimed = {c.topic for c in claims}
    assert sorted(set(SECURITY_TOPICS) - claimed, key=lambda t: int(t[1:])) == []


def test_every_claim_names_a_known_topic() -> None:
    claims, _ = inventory()
    assert [c for c in claims if c.topic not in SECURITY_TOPICS] == []


def test_the_topic_ids_are_t1_to_t19_in_order() -> None:
    assert list(SECURITY_TOPICS) == [f"T{n}" for n in range(1, 20)]


BAD_SNIPPETS = [
    ("import pytest\n@pytest.mark.security()\ndef test_x(): ...\n", "one or more positional"),
    ("import pytest\n@pytest.mark.security(id='T1')\ndef test_x(): ...\n", "one or more positional"),
    ("import pytest\nT = 'T1'\n@pytest.mark.security(T)\ndef test_x(): ...\n", "string literal"),
    ("import pytest\n@pytest.mark.security('T1')\ndef helper(): ...\n", "does not collect"),
    ("import pytest\ndef outer():\n    @pytest.mark.security('T1')\n    def test_x(): ...\n", "does not collect"),
    ("import pytest\nclass Helpers:\n    @pytest.mark.security('T1')\n    def test_x(self): ...\n", "does not collect"),
    ("import pytest\nx = pytest.param(1, marks=pytest.mark.security('T1'))\n", "does not collect"),
    (
        "import pytest\ndef test_x(request):\n    request.node.add_marker(pytest.mark.security('T1'))\n",
        "does not collect",
    ),
    ("import pytest\nm = pytest.mark\n@m.security('T1')\ndef test_x(): ...\n", "behind an alias"),
    ("import pytest\nsec = pytest.mark.security\n@sec('T1')\ndef test_x(): ...\n", "bound to a name"),
    ("from pytest import mark\n@mark.security('T1')\ndef test_x(): ...\n", "behind an alias"),
    ("from pytest import mark as mk\n@mk.security('T1')\ndef test_x(): ...\n", "behind an alias"),
    ("import pytest\nm: object = pytest.mark\n@m.security('T1')\ndef test_x(): ...\n", "behind an alias"),
    ("import pytest\nm, n = pytest.mark, 1\n@m.security('T1')\ndef test_x(): ...\n", "behind an alias"),
    ("import pytest\nm = pytest.mark\nn = m\n@n.security('T1')\ndef test_x(): ...\n", "behind an alias"),
    ("import pytest as pt\n@pt.mark.security('T1')\ndef test_x(): ...\n", "behind an alias"),
    (
        "import pytest\n@pytest.mark.skipif(True, reason='x')\n@pytest.mark.security('T1')\ndef test_x(): ...\n",
        "skipped or xfail",
    ),
    ("import pytest\n@pytest.mark.skip\n@pytest.mark.security('T1')\ndef test_x(): ...\n", "skipped or xfail"),
    ("import pytest\n@pytest.mark.xfail\n@pytest.mark.security('T1')\ndef test_x(): ...\n", "skipped or xfail"),
    (
        "import pytest\npytestmark = pytest.mark.security('T1')\npytestmark = pytest.mark.integration\n",
        "more than once",
    ),
    # Spellings pytest honours that name the generator somewhere the gate does not read a mark from.
    ("import pytest\n@getattr(pytest.mark, 'security')('T1')\ndef test_x(): ...\n", "outside a position"),
    ("import pytest\nmarks = [pytest.mark]\n@marks[0].security('T1')\ndef test_x(): ...\n", "outside a position"),
    ("import pytest\n((m,),) = ((pytest.mark,),)\n@m.security('T1')\ndef test_x(): ...\n", "outside a position"),
    ("import pytest\n(m := pytest.mark)\n@m.security('T1')\ndef test_x(): ...\n", "outside a position"),
    ("import pytest\nregister(pytest.mark)\n", "outside a position"),
    (
        "import pytest\nm = pytest.mark\nmarks = [m]\n@marks[0].security('T1')\ndef test_x(): ...\n",
        "outside a position",
    ),
    ("import pytest\n@pytest.mark.security('T1')()\ndef test_x(): ...\n", "cannot read"),
    ("import pytest\n@(lambda f: f)\ndef test_x(): ...\n", "cannot read"),
    ("import pytest\npytestmark = [getattr(pytest.mark, 'security')('T1')]\n", "cannot read"),
    # Spellings that obtain the generator without writing `.mark`.
    ("import pytest\nm = getattr(pytest, 'mark')\n@m.security('T1')\ndef test_x(): ...\n", "used as a value"),
    ("import pytest\nm = pytest.__dict__['mark']\n@m.security('T1')\ndef test_x(): ...\n", "used as a value"),
    ("import pytest\nm = vars(pytest)['mark']\n@m.security('T1')\ndef test_x(): ...\n", "used as a value"),
    ("import pytest as pt\nm = getattr(pt, 'mark')\n@m.security('T1')\ndef test_x(): ...\n", "used as a value"),
    ("from _pytest.mark import MARK_GEN\n@MARK_GEN.security('T1')\ndef test_x(): ...\n", "internals imported"),
    ("import _pytest.mark as pm\n@pm.MARK_GEN.security('T1')\ndef test_x(): ...\n", "internals imported"),
    ("from pytest import *\n@mark.security('T1')\ndef test_x(): ...\n", "star import"),
    # Markers pytest applies after collection: topic-less `security`, invisible to every source reader.
    ("def test_x(request):\n    request.node.add_marker('security')\n", "added at run time"),
    ("def test_x(request):\n    request.applymarker('security')\n", "added at run time"),
    (
        "def pytest_collection_modifyitems(items):\n    for item in items:\n        item.add_marker('security')\n",
        "added at run time",
    ),
]


@pytest.mark.parametrize(("snippet", "reason"), BAD_SNIPPETS)
def test_the_scanner_rejects_known_bad_snippets(snippet: str, reason: str) -> None:
    _, violations = scan_module(ast.parse(snippet), "test_x.py")
    assert violations and any(reason in v.reason for v in violations), violations


GOOD_SNIPPETS = [
    ("import pytest\n@pytest.mark.security('T1', 'T2')\ndef test_x(): ...\n", ["T1", "T2"]),
    ("import pytest\n@pytest.mark.integration\n@pytest.mark.security('T3')\ndef test_x(): ...\n", ["T3"]),
    ("import pytest\nclass TestX:\n    @pytest.mark.security('T4')\n    def test_y(self): ...\n", ["T4"]),
    ("import pytest\n@pytest.mark.security('T5')\nclass TestX:\n    def test_y(self): ...\n", ["T5"]),
    ("import pytest\npytestmark = pytest.mark.security('T6')\n", ["T6"]),
    ("import pytest\npytestmark = [pytest.mark.integration, pytest.mark.security('T7')]\n", ["T7"]),
    ("import pytest\n@pytest.mark.security('T8')\nasync def test_x(): ...\n", ["T8"]),
    # Other marks may travel through every position the gate reads, aliases included.
    ("import pytest\nP = [pytest.param(1, marks=pytest.mark.integration)]\n", []),
    ("import pytest\nP = [pytest.param(1, marks=[pytest.mark.integration, pytest.mark.slow])]\n", []),
    ("import pytest\nm = pytest.mark\n@m.integration\ndef test_x(): ...\n", []),
    ("import pytest\ndef test_x():\n    with pytest.raises(ValueError):\n        pytest.fail('x')\n", []),
]


@pytest.mark.parametrize(("snippet", "topics"), GOOD_SNIPPETS)
def test_the_scanner_accepts_known_good_snippets(snippet: str, topics: list[str]) -> None:
    claims, violations = scan_module(ast.parse(snippet), "test_x.py")
    assert violations == [] and [c.topic for c in claims] == topics


def _item(relpath: str, function: str, *topics: str, cls: str | None = None) -> CollectedItem:
    return CollectedItem(relpath, cls, function, topics)


CLAIMS = [
    Claim("T6", "a.py::pytestmark"),
    Claim("T4", "a.py::TestX"),
    Claim("T1", "a.py::TestX::test_y"),
    Claim("T2", "a.py::test_z"),
    Claim("T3", "b.py::test_w"),
]


def test_the_cross_check_is_quiet_when_pytest_and_the_gate_agree_layer_by_layer() -> None:
    collected = [_item("a.py", "test_y", "T1", "T4", "T6", cls="TestX"), _item("a.py", "test_z", "T2", "T6")]
    assert collection_mismatches(collected, CLAIMS, started_modules={"a.py"}) == []


def test_a_topic_pytest_sees_but_the_gate_did_not_read_is_a_mismatch() -> None:
    collected = [_item("a.py", "test_z", "T2", "T6", "T9")]
    assert collection_mismatches(collected, CLAIMS, started_modules=None) == [
        "a.py::test_z: pytest sees security('T2', 'T6', 'T9'), the gate read ('T6', 'T2')"
    ]


def test_a_topic_the_gate_read_but_pytest_does_not_carry_is_a_mismatch() -> None:
    collected = [_item("a.py", "test_y", "T1", "T6", cls="TestX")]
    problems = collection_mismatches(collected, CLAIMS, started_modules=None)
    assert problems == ["a.py::TestX::test_y: pytest sees security('T1', 'T6'), the gate read ('T6', 'T4', 'T1')"]


def test_a_nested_class_is_located_by_its_qualified_name() -> None:
    collected = [_item("a.py", "test_y", "T1", "T4", "T6", cls="TestOuter.TestX")]
    assert collection_mismatches(collected, CLAIMS, started_modules=None) == [
        "a.py::TestOuter::TestX::test_y: pytest sees security('T1', 'T4', 'T6'), the gate read ('T6',)"
    ]


def test_a_claim_no_collected_test_carries_is_dead_when_its_module_was_started() -> None:
    collected = [_item("a.py", "test_z", "T2", "T6")]
    assert collection_mismatches(collected, CLAIMS, started_modules=None) == []
    assert collection_mismatches(collected, CLAIMS, started_modules={"a.py"}) == [
        "a.py::TestX: the gate read a claim here, but no test under it ran",
        "a.py::TestX::test_y: the gate read a claim here, but no test under it ran",
    ]


def test_claims_in_modules_pytest_never_started_are_not_dead() -> None:
    collected = [_item("a.py", "test_y", "T1", "T4", "T6", cls="TestX"), _item("a.py", "test_z", "T2", "T6")]
    assert collection_mismatches(collected, CLAIMS, started_modules={"a.py"}) == []
    assert collection_mismatches([], CLAIMS, started_modules={"b.py"}) == [
        "b.py::test_w: the gate read a claim here, but no test under it ran"
    ]


@pytest.mark.parametrize("relpath", ["helpers.py", "conftest.py", "unit/support.py", "unit/testing_tools.py"])
def test_a_claim_in_a_module_pytest_does_not_collect_is_a_violation(relpath: str) -> None:
    source = "import pytest\n@pytest.mark.security('T1')\ndef test_x(): ...\n"
    _, violations = scan_module(ast.parse(source), relpath)
    assert [v.reason for v in violations] == ["a claim in a module pytest never collects"]
    assert (
        scan_module(ast.parse(source), "unit/test_x.py")[1] == scan_module(ast.parse(source), "unit/x_test.py")[1] == []
    )


def test_a_malformed_security_marker_is_reported_even_when_both_sides_have_no_topics() -> None:
    collected = [CollectedItem("a.py", None, "test_plain", (), malformed_markers=1)]
    assert collection_mismatches(collected, CLAIMS, started_modules=None) == [
        "a.py::test_plain: a security marker without topic ids or with keywords"
    ]


def test_a_security_marker_on_an_item_that_is_not_a_test_function_is_reported() -> None:
    marked = CollectedItem("things.yml", None, "custom", ("T1",), is_function=False)
    unmarked = CollectedItem("things.yml", None, "custom", (), is_function=False)
    assert collection_mismatches([marked], CLAIMS, started_modules=None) == [
        "things.yml::custom: a security marker on an item that is not a test function"
    ]
    assert collection_mismatches([unmarked], CLAIMS, started_modules=None) == []


def test_a_security_marker_on_a_test_whose_every_case_is_marked_skipped_is_reported_not_counted() -> None:
    skipped = CollectedItem("a.py", None, "test_z", ("T2", "T6"), skipped=True)
    assert collection_mismatches([skipped], CLAIMS, started_modules=None) == [
        "a.py::test_z: a security marker on a test no case of which ran (skipped or xfail)"
    ]
    one_case_runs = [skipped, CollectedItem("a.py", None, "test_z", ("T2", "T6"))]
    assert collection_mismatches(one_case_runs, CLAIMS, started_modules=None) == []
    unclaimed = CollectedItem("c.py", None, "test_plain", (), skipped=True)
    assert collection_mismatches([unclaimed], CLAIMS, started_modules=None) == []


def test_the_integration_marker_must_agree_with_the_directory() -> None:
    misplaced = CollectedItem("unit/test_u.py", None, "test_x", (), integration=True)
    unmarked = CollectedItem("integration/local/test_i.py", None, "test_y", ())
    in_place = [
        CollectedItem("unit/test_u.py", None, "test_x", ()),
        CollectedItem("integration/local/test_i.py", None, "test_y", (), integration=True),
    ]
    assert collection_mismatches([misplaced, unmarked], [], started_modules=None) == [
        "unit/test_u.py::test_x: integration marker outside tests/integration/ — no ./dev ci run executes this test",
        "integration/local/test_i.py::test_y: no integration marker under tests/integration/ — the unit tiers "
        "would run it without the harness",
    ]
    assert collection_mismatches(in_place, [], started_modules=None) == []


def test_a_whole_tree_run_reports_claims_in_modules_pytest_never_started() -> None:
    collected = [_item("a.py", "test_y", "T1", "T4", "T6", cls="TestX"), _item("a.py", "test_z", "T2", "T6")]
    assert collection_mismatches(collected, CLAIMS, started_modules={"a.py"}, require_started=True) == [
        "b.py::test_w: the gate read a claim here, but pytest never started this module"
    ]


def test_a_nested_test_class_is_rejected_rather_than_read() -> None:
    source = (
        "import pytest\nclass TestOuter:\n    class TestInner:\n        @pytest.mark.security('T1')\n"
        "        def test_x(self): ...\n"
    )
    claims, violations = scan_module(ast.parse(source), "test_x.py")
    assert claims == []
    assert "a nested test class is not read; flatten it" in [v.reason for v in violations]


def test_a_deselected_test_neither_runs_nor_leaves_a_dead_claim() -> None:
    deselected = CollectedItem("a.py", None, "test_z", ("T2", "T6"), deselected=True)
    running = CollectedItem("a.py", "TestX", "test_y", ("T1", "T4", "T6"))
    assert collection_mismatches([deselected, running], CLAIMS, started_modules={"a.py"}) == []
