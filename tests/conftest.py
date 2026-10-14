"""Cross-check of the security inventory against what pytest actually ran.

The inventory gate reads `@pytest.mark.security(...)` from source, so the integration tier counts without
Docker. Source reading has a fixed grammar; pytest's marker and collection machinery has not. These hooks
close the gap in the one place that knows the truth: the session itself. Before `-m` deselection, every
collected item's `security` topics must equal the topics the gate read at that item's locations (so the
integration tier is checked in the unit run too). At the end of the session the same comparison runs over
the tests that actually executed — with the markers they carried when they ran — plus the tests the run
deselected; every claim in a module pytest started collecting must be carried by one of them; a test that
ran in no case (skipped, xfail) may not carry one; only test functions may carry the marker; the
`integration` marker must agree with the test's directory; and in a run over the whole tree every module
holding a claim must have started. A spelling the gate does not read, a marker added or a test dropped by
any later hook, a test whose protocol was intercepted, a module that skips itself at import time, a class
or function that opts out, or a run-time skip therefore cannot keep a claim alive. What this proves is
that pytest ran the call phase of a test carrying the marker — not what the body did: a hook or fixture that
replaces the test body (`pytest_pyfunc_call`, a swapped `item.runtest`, `request.node.obj`) is inside the
trust boundary. Trust boundary: the tests, conftests and plugins of this repository (pytest-cov,
hypothesis) are trusted code; a hook that replaces a test body, forges test reports or resets
`session.exitstatus` after this one is outside the gate's model, as is a test deselected for good by a
`--deselect`/`-k` in the addopts or by a hook that reports its own deselection (indistinguishable from a
tier choice).
"""

import sys
from collections.abc import Generator, Sequence
from pathlib import Path

import pytest

from tests.unit.test_security_inventory import Claim, CollectedItem, collection_mismatches, inventory

pytest_plugins = ["pytester"]

TESTS_DIR = Path(__file__).resolve().parent
CLAIMS = pytest.StashKey[list[Claim]]()
STARTED_MODULES = pytest.StashKey[set[str]]()
DESELECTED = pytest.StashKey[list[CollectedItem]]()
RAN = pytest.StashKey[list[CollectedItem]]()
SKIPPED = pytest.StashKey[list[CollectedItem]]()
LOOP_ENTERED = pytest.StashKey[bool]()


def _relpath(path: Path) -> str:
    return path.relative_to(TESTS_DIR).as_posix()


def _claims(config: pytest.Config) -> list[Claim]:
    if CLAIMS not in config.stash:
        config.stash[CLAIMS] = inventory(TESTS_DIR)[0]
    return config.stash[CLAIMS]


def _view(item: pytest.Item, *, skipped: bool = False, deselected: bool = False) -> CollectedItem:
    marks = list(item.iter_markers("security"))
    function = item if isinstance(item, pytest.Function) else None
    return CollectedItem(
        relpath=_relpath(Path(item.path)),
        class_qualname=function.cls.__qualname__ if function is not None and function.cls is not None else None,
        function_name=function.originalname if function is not None else item.name,
        topics=tuple(str(arg) for mark in marks for arg in mark.args),
        malformed_markers=sum(1 for mark in marks if not mark.args or mark.kwargs),
        is_function=function is not None,
        integration=item.get_closest_marker("integration") is not None,
        skipped=skipped,
        deselected=deselected,
    )


def _fail_on(problems: list[str]) -> None:
    if problems:
        raise pytest.UsageError(
            "security inventory: pytest's markers and the gate's reading differ\n  " + "\n  ".join(problems)
        )


def pytest_collectstart(collector: pytest.Collector) -> None:
    if isinstance(collector, pytest.Module):
        collector.config.stash.setdefault(STARTED_MODULES, set()).add(_relpath(Path(collector.path)))


def pytest_deselected(items: Sequence[pytest.Item]) -> None:
    for item in items:
        item.config.stash.setdefault(DESELECTED, []).append(_view(item, deselected=True))


@pytest.hookimpl(tryfirst=True)
def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    _fail_on(collection_mismatches([_view(item) for item in items], _claims(config), started_modules=None))


@pytest.hookimpl(wrapper=True)
def pytest_runtestloop(session: pytest.Session) -> Generator[None, object, object]:
    # Only a session that reaches the test loop can be judged by what ran; `--fixtures`, `--cache-show` and
    # the like go through the session without it. A wrapper sees the loop whatever other implementation
    # ends up running it.
    session.config.stash[LOOP_ENTERED] = True
    return (yield)


@pytest.hookimpl(wrapper=True)
def pytest_runtest_makereport(
    item: pytest.Item, call: pytest.CallInfo[None]
) -> Generator[None, pytest.TestReport, pytest.TestReport]:
    report = yield
    # The call phase is the only proof a test ran; a skip in setup or call, and an xfail, ran nothing that
    # proves a topic. The markers are read here, at run time, not from the collection snapshot.
    if report.when == "call" and report.outcome != "skipped":
        item.config.stash.setdefault(RAN, []).append(_view(item))
    elif report.outcome == "skipped":
        item.config.stash.setdefault(SKIPPED, []).append(_view(item, skipped=True))
    return report


@pytest.hookimpl(trylast=True)
def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    config = session.config
    # Only a session that got to run its tests can say what ran (a module that skips itself at import time
    # leaves nothing collected, which is exactly a dead claim); runs that ended early are judged by their own
    # exit status, and `-x`/`--maxfail` end the loop early with the ordinary failure status (`--sw` ends with
    # INTERRUPTED), so what did not run then proves nothing either way.
    if exitstatus not in {pytest.ExitCode.OK, pytest.ExitCode.TESTS_FAILED, pytest.ExitCode.NO_TESTS_COLLECTED}:
        return
    if exitstatus == pytest.ExitCode.TESTS_FAILED and session.shouldfail:
        return
    # Modes that never reach the test loop, and modes that enter it but run nothing.
    if not config.stash.get(LOOP_ENTERED, False):
        return
    if config.getoption("collectonly") or config.getoption("setuponly"):
        return
    # A node id collects part of a module on purpose, and `--lf` filters the previously passed tests out while
    # collecting (silently, before any deselection event), so only a run without either can tell a dead claim
    # from a test that was never collected; a run over the whole tree can also tell a module that never started.
    whole_modules = not config.getoption("lf", False) and not any("::" in str(arg) for arg in config.args)
    whole_tree = whole_modules and all(
        (config.invocation_params.dir / str(arg)).resolve() in {TESTS_DIR, TESTS_DIR.parent} for arg in config.args
    )
    started = config.stash.get(STARTED_MODULES, set()) if whole_modules else None
    seen = [*config.stash.get(RAN, []), *config.stash.get(SKIPPED, []), *config.stash.get(DESELECTED, [])]
    problems = collection_mismatches(seen, _claims(config), started, require_started=whole_tree)
    if problems:
        sys.stderr.write(
            "\nERROR: security inventory: what ran and the gate's reading differ\n  " + "\n  ".join(problems) + "\n"
        )
        session.exitstatus = pytest.ExitCode.USAGE_ERROR
