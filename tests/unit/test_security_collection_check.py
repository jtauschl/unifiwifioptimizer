"""The collection-time cross-check wired into tests/conftest.py, run against pytest itself: a marker
spelling the inventory gate does not read fails the session, and plain spellings pass."""

from pathlib import Path

import pytest

CONFTEST = Path(__file__).resolve().parents[1] / "conftest.py"
INI = "[pytest]\nmarkers =\n    security(id, ...): topic\n    integration: harness\n    slow: other\n"

UNREADABLE_SPELLINGS = {
    "star-import": "from pytest import *\n@mark.security('T1')\ndef test_x(): ...\n",
    "mark-generator": (
        "import pytest\nmg = pytest.MarkGenerator(_ispytest=True)\n@mg.security('T1')\ndef test_x(): ...\n"
    ),
    "mark-decorator": (
        "import pytest\n"
        "@pytest.MarkDecorator(pytest.Mark('security', ('T1',), {}, _ispytest=True), _ispytest=True)\n"
        "def test_x(): ...\n"
    ),
    "importorskip-internals": (
        "import pytest\nmg = pytest.importorskip('_pytest.mark').MARK_GEN\n@mg.security('T1')\ndef test_x(): ...\n"
    ),
    "dynamic-dict": "import pytest\nm = globals()['pytest'].__dict__['mark']\n@m.security('T1')\ndef test_x(): ...\n",
    "helper-reexport": "from helpers import m\n@m.security('T1')\ndef test_x(): ...\n",
}
HELPERS = "import pytest\nm = pytest.mark\n"
TOPICLESS_SPELLINGS = {
    "bare": "import pytest\nmg = pytest.MarkGenerator(_ispytest=True)\n@mg.security\ndef test_x(): ...\n",
    "keyword": "import pytest\nmg = pytest.MarkGenerator(_ispytest=True)\n@mg.security(id='T1')\ndef test_x(): ...\n",
}
CUSTOM_ITEM_CONFTEST = (
    "import pytest\n"
    "class Thing(pytest.Item):\n"
    "    def runtest(self): pass\n"
    "class Things(pytest.File):\n"
    "    def collect(self):\n"
    "        item = Thing.from_parent(self, name='custom')\n"
    "        item.own_markers.append(pytest.Mark('security', ('T1',), {}, _ispytest=True))\n"
    "        yield item\n"
    "def pytest_collect_file(parent, file_path):\n"
    "    if file_path.suffix == '.yml':\n"
    "        return Things.from_parent(parent, path=file_path)\n"
)
LATE_CONFTEST = (
    "import pytest\n"
    "def pytest_collection_modifyitems(items):\n"
    "    for item in items:\n"
    "        item.own_markers.append(pytest.Mark('security', ('T1',), {}, _ispytest=True))\n"
)


def run(
    pytester: pytest.Pytester, *args: str, cache: bool = False, files: dict[str, str] | None = None, **more: str
) -> pytest.RunResult:
    pytester.makeini(INI)
    pytester.makeconftest(CONFTEST.read_text(encoding="utf-8"))
    pytester.makepyfile(helpers=HELPERS, **(files or {}), **more)
    plugins = () if cache else ("-p", "no:cacheprovider")
    return pytester.runpytest_inprocess(*plugins, *args)


@pytest.mark.parametrize("source", UNREADABLE_SPELLINGS.values(), ids=UNREADABLE_SPELLINGS.keys())
def test_a_marker_pytest_honours_but_the_gate_cannot_read_fails_the_session(
    pytester: pytest.Pytester, source: str
) -> None:
    result = run(pytester, test_spelling=source)
    assert result.ret == pytest.ExitCode.USAGE_ERROR
    result.stderr.re_match_lines([r".*security inventory: .* and the gate's reading differ"])
    result.stderr.re_match_lines([r".*test_spelling\.py::test_x: pytest sees security\('T1',\), the gate read \(\)"])


@pytest.mark.parametrize("source", TOPICLESS_SPELLINGS.values(), ids=TOPICLESS_SPELLINGS.keys())
def test_a_security_marker_without_topics_fails_the_session(pytester: pytest.Pytester, source: str) -> None:
    result = run(pytester, test_spelling=source)
    assert result.ret == pytest.ExitCode.USAGE_ERROR
    result.stderr.re_match_lines([r".*test_spelling\.py::test_x: a security marker without topic ids or with keywords"])


def test_a_marker_added_by_a_later_collection_hook_fails_the_session(pytester: pytest.Pytester) -> None:
    pytester.mkpydir("sub")
    result = run(pytester, files={"sub/conftest": LATE_CONFTEST, "sub/test_late": "def test_x(): ...\n"})
    assert result.ret == pytest.ExitCode.USAGE_ERROR
    result.stderr.re_match_lines([r".*sub/test_late\.py::test_x: pytest sees security\('T1',\), the gate read \(\)"])


def test_last_failed_reruns_do_not_report_the_passed_tests_as_dead_claims(pytester: pytest.Pytester) -> None:
    module = (
        "import pytest\n@pytest.mark.security('T1')\ndef test_a(): ...\n"
        "@pytest.mark.security('T2')\ndef test_b(): assert False\n"
    )
    first = run(pytester, cache=True, test_lf=module)
    first.assert_outcomes(passed=1, failed=1)
    second = pytester.runpytest_inprocess("--lf")
    assert second.ret == pytest.ExitCode.TESTS_FAILED
    second.assert_outcomes(failed=1)


def test_a_claim_on_a_class_pytest_cannot_collect_is_dead_in_a_whole_module_run(pytester: pytest.Pytester) -> None:
    # pytest skips a Test class with __init__ (with a collection warning); the marker on it proves nothing.
    uncollectable = (
        "import pytest\n@pytest.mark.security('T1')\nclass TestX:\n    def __init__(self): ...\n"
        "    def test_y(self): ...\ndef test_x(): ...\n"
    )
    result = run(pytester, "-W", "ignore::pytest.PytestCollectionWarning", test_dead=uncollectable)
    assert result.ret == pytest.ExitCode.USAGE_ERROR
    result.stderr.re_match_lines([r".*test_dead\.py::TestX: the gate read a claim here, but no test under it ran"])
    result = run(
        pytester, "-W", "ignore::pytest.PytestCollectionWarning", "test_dead.py::test_x", test_dead=uncollectable
    )
    assert result.ret == pytest.ExitCode.OK


def test_plain_spellings_in_every_readable_position_pass(pytester: pytest.Pytester) -> None:
    result = run(
        pytester,
        test_plain=(
            "import pytest\n"
            "pytestmark = [pytest.mark.security('T6'), pytest.mark.slow]\n"
            "@pytest.mark.security('T4')\n"
            "class TestX:\n"
            "    @pytest.mark.security('T1', 'T5')\n"
            "    def test_y(self): ...\n"
            "@pytest.mark.security('T2')\n"
            "@pytest.mark.parametrize('n', [pytest.param(1, marks=pytest.mark.slow), 2])\n"
            "def test_z(n): ...\n"
            "def test_unmarked(): ...\n"
        ),
    )
    assert result.ret == pytest.ExitCode.OK
    result.assert_outcomes(passed=4)


def test_a_node_id_selection_does_not_report_the_deselected_claims_as_dead(pytester: pytest.Pytester) -> None:
    result = run(
        pytester,
        "test_two.py::test_a",
        test_two=(
            "import pytest\n@pytest.mark.security('T1')\ndef test_a(): ...\n"
            "@pytest.mark.security('T2')\ndef test_b(): ...\n"
        ),
    )
    assert result.ret == pytest.ExitCode.OK
    result.assert_outcomes(passed=1)


def test_a_security_marker_on_a_custom_item_fails_the_session(pytester: pytest.Pytester) -> None:
    pytester.mkpydir("sub")
    pytester.makefile(".yml", **{"sub/things": ""})
    result = run(pytester, files={"sub/conftest": CUSTOM_ITEM_CONFTEST})
    assert result.ret == pytest.ExitCode.USAGE_ERROR
    result.stderr.re_match_lines(
        [r".*sub/things\.yml::custom: a security marker on an item that is not a test function"]
    )


def test_a_keyword_selection_keeps_the_dead_claim_direction(pytester: pytest.Pytester) -> None:
    uncollectable = (
        "import pytest\n@pytest.mark.security('T1')\nclass TestX:\n    def __init__(self): ...\n"
        "    def test_y(self): ...\ndef test_x(): ...\n"
    )
    result = run(pytester, "-W", "ignore::pytest.PytestCollectionWarning", "-k", "test_x", test_dead=uncollectable)
    assert result.ret == pytest.ExitCode.USAGE_ERROR
    result.stderr.re_match_lines([r".*test_dead\.py::TestX: the gate read a claim here, but no test under it ran"])


DEAD_MODULES = {
    "importorskip": "import pytest\npytest.importorskip('nothing')\n@pytest.mark.security('T1')\ndef test_x(): ...\n",
    "module-dunder-test": "import pytest\n__test__ = False\n@pytest.mark.security('T1')\ndef test_x(): ...\n",
    "unittest-skiptest": (
        "import pytest, unittest\nraise unittest.SkipTest('no')\n@pytest.mark.security('T1')\ndef test_x(): ...\n"
    ),
    "skip-via-helper": (
        "import pytest\ndef bail():\n    pytest.skip('no', allow_module_level=True)\nbail()\n"
        "@pytest.mark.security('T1')\ndef test_x(): ...\n"
    ),
    "class-dunder-test": (
        "import pytest\nclass TestX:\n    __test__ = False\n    @pytest.mark.security('T1')\n"
        "    def test_y(self): ...\ndef test_other(): ...\n"
    ),
    "inherited-dunder-test": (
        "import pytest\nclass Base:\n    __test__ = False\nclass TestX(Base):\n    @pytest.mark.security('T1')\n"
        "    def test_y(self): ...\ndef test_other(): ...\n"
    ),
    "function-dunder-test": (
        "import pytest\n@pytest.mark.security('T1')\ndef test_x(): ...\ntest_x.__test__ = False\n"
        "def test_other(): ...\n"
    ),
}


@pytest.mark.parametrize("source", DEAD_MODULES.values(), ids=DEAD_MODULES.keys())
def test_a_claim_in_a_started_module_that_yields_no_test_for_it_is_dead(pytester: pytest.Pytester, source: str) -> None:
    result = run(pytester, test_dead=source)
    assert result.ret == pytest.ExitCode.USAGE_ERROR
    result.stderr.re_match_lines([r".*test_dead\.py::.*: the gate read a claim here, but no test under it ran"])


DROPPING_CONFTEST = (
    "def pytest_collection_modifyitems(items):\n    items[:] = [item for item in items if item.name != 'test_x']\n"
)


def test_a_test_dropped_by_a_later_hook_leaves_a_dead_claim(pytester: pytest.Pytester) -> None:
    pytester.mkpydir("sub")
    result = run(
        pytester,
        files={
            "sub/conftest": DROPPING_CONFTEST,
            "sub/test_dropped": "import pytest\n@pytest.mark.security('T1')\ndef test_x(): ...\ndef test_y(): ...\n",
        },
    )
    assert result.ret == pytest.ExitCode.USAGE_ERROR
    result.stderr.re_match_lines(
        [r".*sub/test_dropped\.py::test_x: the gate read a claim here, but no test under it ran"]
    )


def test_a_claimed_test_deselected_by_a_marker_expression_is_not_dead(pytester: pytest.Pytester) -> None:
    module = "import pytest\n@pytest.mark.integration\n@pytest.mark.security('T1')\ndef test_a(): ...\n"
    pytester.mkpydir("integration")
    files = {"integration/test_sel": module, "test_other": "def test_b(): ...\n"}
    result = run(pytester, "-m", "not integration", files=files)
    assert result.ret == pytest.ExitCode.OK
    result.assert_outcomes(passed=1, deselected=1)


ALWAYS_SKIPPED = {
    "module-skip": "import pytest\npytestmark = pytest.mark.skip\n@pytest.mark.security('T1')\ndef test_x(): ...\n",
    "class-skipif": (
        "import pytest\n@pytest.mark.skipif(True, reason='x')\nclass TestX:\n"
        "    @pytest.mark.security('T1')\n    def test_y(self): ...\n"
    ),
    "empty-parameter-set": (
        "import pytest\n@pytest.mark.security('T1')\n@pytest.mark.parametrize('n', [])\ndef test_x(n): ...\n"
    ),
    "all-parameters-skipped": (
        "import pytest\n@pytest.mark.security('T1')\n"
        "@pytest.mark.parametrize('n', [pytest.param(1, marks=pytest.mark.skip)])\ndef test_x(n): ...\n"
    ),
}


@pytest.mark.parametrize("source", ALWAYS_SKIPPED.values(), ids=ALWAYS_SKIPPED.keys())
def test_a_claim_on_a_test_whose_every_case_is_marked_skipped_fails_the_session(
    pytester: pytest.Pytester, source: str
) -> None:
    result = run(pytester, test_skipped=source)
    assert result.ret == pytest.ExitCode.USAGE_ERROR
    result.stderr.re_match_lines(
        [r".*test_skipped\.py::.*: a security marker on a test no case of which ran \(skipped or xfail\)"]
    )


def test_a_whole_tree_run_reports_a_claimed_module_pytest_never_started(pytester: pytest.Pytester) -> None:
    pytester.mkpydir("sub")
    files = {
        "sub/conftest": "collect_ignore = ['test_ignored.py']\n",
        "sub/test_ignored": "import pytest\n@pytest.mark.security('T1')\ndef test_x(): ...\n",
        "sub/test_seen": "def test_y(): ...\n",
    }
    result = run(pytester, files=files)
    assert result.ret == pytest.ExitCode.USAGE_ERROR
    result.stderr.re_match_lines(
        [r".*sub/test_ignored\.py::test_x: the gate read a claim here, but pytest never started this module"]
    )
    result = run(pytester, "sub/test_seen.py", files=files)
    assert result.ret == pytest.ExitCode.OK


def test_an_integration_marker_outside_the_integration_tree_fails_the_session(pytester: pytest.Pytester) -> None:
    pytester.mkpydir("unit")
    result = run(
        pytester,
        files={
            "unit/test_misplaced": (
                "import pytest\n@pytest.mark.integration\n@pytest.mark.security('T3')\ndef test_x(): ...\n"
            )
        },
    )
    assert result.ret == pytest.ExitCode.USAGE_ERROR
    result.stderr.re_match_lines(
        [r".*unit/test_misplaced\.py::test_x: integration marker outside tests/integration/.*"]
    )


def test_an_unmarked_test_under_the_integration_tree_fails_the_session(pytester: pytest.Pytester) -> None:
    pytester.mkpydir("integration")
    result = run(pytester, files={"integration/test_unmarked": "def test_y(): ...\n"})
    assert result.ret == pytest.ExitCode.USAGE_ERROR
    result.stderr.re_match_lines(
        [r".*integration/test_unmarked\.py::test_y: no integration marker under tests/integration/.*"]
    )


def test_one_skipped_case_among_running_cases_keeps_the_claim(pytester: pytest.Pytester) -> None:
    module = (
        "import pytest\n@pytest.mark.security('T1')\n"
        "@pytest.mark.parametrize('n', [pytest.param(1, marks=pytest.mark.skip), 2])\ndef test_x(n): ...\n"
    )
    result = run(pytester, test_partial=module)
    assert result.ret == pytest.ExitCode.OK
    result.assert_outcomes(passed=1, skipped=1)


CLAIMED = "import pytest\n@pytest.mark.security('T1')\ndef test_x(): ...\ndef test_other(): ...\n"
AFTER_COLLECTION = {
    "drop-after-finish": (
        "import pytest\n@pytest.hookimpl(wrapper=True)\ndef pytest_collection_finish(session):\n    yield\n"
        "    session.items[:] = [i for i in session.items if i.name != 'test_x']\n"
    ),
    "mark-after-finish": (
        "import pytest\n@pytest.hookimpl(wrapper=True)\ndef pytest_collection_finish(session):\n    yield\n"
        "    for item in session.items:\n"
        "        if item.name == 'test_other':\n"
        "            item.own_markers.append(pytest.Mark('security', ('T2',), {}, _ispytest=True))\n"
    ),
    "protocol-intercepted": (
        "def pytest_runtest_protocol(item, nextitem):\n    return True if item.name == 'test_x' else None\n"
    ),
}


@pytest.mark.parametrize("conftest", AFTER_COLLECTION.values(), ids=AFTER_COLLECTION.keys())
def test_what_a_hook_changes_after_collection_is_judged_by_what_ran(pytester: pytest.Pytester, conftest: str) -> None:
    pytester.mkpydir("sub")
    result = run(pytester, files={"sub/conftest": conftest, "sub/test_late": CLAIMED})
    assert result.ret == pytest.ExitCode.USAGE_ERROR
    result.stderr.re_match_lines([r".*security inventory: what ran and the gate's reading differ"])


RUN_TIME_SKIPS = {
    "unittest-skipif": (
        "import pytest, unittest\n@unittest.skipIf(True, 'no')\n@pytest.mark.security('T1')\ndef test_x(): ...\n"
    ),
    "setup-module-skip": (
        "import pytest\ndef setup_module():\n    pytest.skip('no')\n@pytest.mark.security('T1')\ndef test_x(): ...\n"
    ),
    "skip-inside-the-test": "import pytest\n@pytest.mark.security('T1')\ndef test_x():\n    pytest.skip('no')\n",
    "xfail": "import pytest\n@pytest.mark.xfail\n@pytest.mark.security('T1')\ndef test_x():\n    assert False\n",
}


@pytest.mark.parametrize("source", RUN_TIME_SKIPS.values(), ids=RUN_TIME_SKIPS.keys())
def test_a_claim_on_a_test_skipped_at_run_time_fails_the_session(pytester: pytest.Pytester, source: str) -> None:
    result = run(pytester, test_runtime=source)
    assert result.ret == pytest.ExitCode.USAGE_ERROR
    result.stderr.re_match_lines([r".*test_runtime\.py::test_x: a security marker on a test no case of which ran.*"])


def test_collect_only_does_not_judge_what_ran(pytester: pytest.Pytester) -> None:
    result = run(pytester, "--collect-only", test_co=CLAIMED)
    assert result.ret == pytest.ExitCode.OK


def test_an_early_stop_on_the_first_failure_keeps_the_ordinary_failure_status(pytester: pytest.Pytester) -> None:
    module = (
        "import pytest\n@pytest.mark.security('T1')\ndef test_a(): assert False\n"
        "@pytest.mark.security('T2')\ndef test_b(): ...\n"
    )
    result = run(pytester, "-x", test_stop=module)
    assert result.ret == pytest.ExitCode.TESTS_FAILED
    result.assert_outcomes(failed=1)
    assert not any("security inventory" in line for line in result.stderr.lines)


@pytest.mark.parametrize(
    "option", ["--fixtures", "--fixtures-per-test", "--setup-plan", "--setup-only", "--cache-show", "--collect-only"]
)
def test_modes_that_run_nothing_do_not_judge_what_ran(pytester: pytest.Pytester, option: str) -> None:
    result = run(pytester, option, cache=option == "--cache-show", test_mode=CLAIMED)
    assert result.ret == pytest.ExitCode.OK
    assert not any("security inventory" in line for line in result.stderr.lines)
