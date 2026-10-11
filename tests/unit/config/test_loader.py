import threading
import time

import pytest

from unifiwifioptimizer.config.loader import (
    MAX_ALIASES,
    MAX_DEPTH,
    MAX_NODES,
    MAX_NUMBER_CHARS,
    StrictLoader,
    _deadline,
    parse_yaml,
)
from unifiwifioptimizer.domain.errors import ConfigError, ConfigTimeoutError


def test_yaml_12_core_scalars_only() -> None:
    document = parse_yaml(
        "a: off\nb: no\nc: yes\nd: on\ne: true\nf: false\ng: 1:30\nh: 1_000\ni: 0x1f\nj: 0o17\nk: 12\nl: 1.5\n"
        "m: ~\nn: null\no:\np: '12'\nq: 1e3\nr: True\n"
    )
    assert document == {
        "a": "off", "b": "no", "c": "yes", "d": "on", "e": True, "f": False, "g": "1:30", "h": "1_000", "i": 31,
        "j": 15, "k": 12, "l": 1.5, "m": None, "n": None, "o": None, "p": "12", "q": 1000.0, "r": "True",
    }  # fmt: skip
    assert parse_yaml("a: 09\nb: 010\nc: +08\nd: -0\ne: 2026-10-10\nf: trueish\ng: 1e3\nh: xtrue\ni: falsey\n") == {
        "a": 9, "b": 10, "c": 8, "d": 0, "e": "2026-10-10", "f": "trueish", "g": 1000.0, "h": "xtrue", "i": "falsey",
    }  # fmt: skip


@pytest.mark.parametrize("text", ["1e9999", "-1e9999", "1e400", ".inf", "-.Inf", ".NaN"])
def test_non_finite_floats_are_refused_however_they_are_spelled(text: str) -> None:
    with pytest.raises(ConfigError) as exc:
        parse_yaml(f"a: 1\nb: {text}\n")
    assert exc.value.path == "line 2" and exc.value.detail == "expected a finite number"


def test_overlong_numbers_are_refused_before_conversion() -> None:
    with pytest.raises(ConfigError) as exc:
        parse_yaml("a: " + "9" * 5000 + "\n")
    assert exc.value.path == "line 1" and exc.value.detail == f"a number has at most {MAX_NUMBER_CHARS} characters"
    with pytest.raises(ConfigError, match=f"at most {MAX_NUMBER_CHARS} characters"):
        parse_yaml("a: " + "9" * (MAX_NUMBER_CHARS + 1) + "\n")
    with pytest.raises(ConfigError, match=f"at most {MAX_NUMBER_CHARS} characters"):
        parse_yaml("a: 1." + "0" * MAX_NUMBER_CHARS + "\n")
    assert parse_yaml("a: " + "9" * MAX_NUMBER_CHARS + "\n") == {"a": int("9" * MAX_NUMBER_CHARS)}


def test_non_scalar_keys_are_rejected_with_the_line() -> None:
    with pytest.raises(ConfigError) as exc:
        parse_yaml("a: 1\n? [x]\n: 2\n")
    assert exc.value.path == "line 2" and exc.value.detail == "a key must be a scalar"
    with pytest.raises(ConfigError, match="a key must be a scalar"):
        parse_yaml("{[a]: 1}")


@pytest.mark.parametrize("text", ["a: .inf", "a: -.Inf", "a: .nan", "a: [1, .NaN]"])
def test_non_finite_numbers_are_rejected(text: str) -> None:
    with pytest.raises(ConfigError, match="finite"):
        parse_yaml(text)


def test_duplicate_keys_are_rejected_with_the_line() -> None:
    with pytest.raises(ConfigError) as exc:
        parse_yaml("a: 1\nb:\n  c: 1\n  c: 2\n")
    assert exc.value.path == "line 4" and exc.value.detail == "duplicate key"


def test_nesting_depth_is_capped() -> None:
    assert parse_yaml("[" * MAX_DEPTH + "]" * MAX_DEPTH) is not None
    with pytest.raises(ConfigError, match=f"deeper than {MAX_DEPTH}"):
        parse_yaml("[" * (MAX_DEPTH + 1) + "]" * (MAX_DEPTH + 1))
    block = "".join(f"{'  ' * level}k{level}:\n" for level in range(MAX_DEPTH + 1)) + "  " * (MAX_DEPTH + 1) + "v"
    with pytest.raises(ConfigError, match=f"deeper than {MAX_DEPTH}"):
        parse_yaml(block)


def test_node_count_is_capped() -> None:
    assert len(parse_yaml("[" + ", ".join("1" for _ in range(MAX_NODES - 1)) + "]")) == MAX_NODES - 1  # type: ignore[arg-type]
    with pytest.raises(ConfigError, match=f"more than {MAX_NODES} nodes"):
        parse_yaml("[" + ", ".join("1" for _ in range(MAX_NODES)) + "]")


def test_alias_expansion_within_the_caps_stays_cheap() -> None:
    # 16 levels x 3 aliases = 48 aliases: inside every cap, 3**16 leaves once expanded; nothing may
    # walk that tree.
    text = "a0: &a0 [1.5, 2.5, 3.5]\n"
    for level in range(1, 17):
        text += f"a{level}: &a{level} [*a{level - 1}, *a{level - 1}, *a{level - 1}]\n"
    started = time.monotonic()
    parse_yaml(text)
    assert time.monotonic() - started < 2.0


def test_billion_laughs_is_stopped_by_the_alias_cap() -> None:
    text = "a: &a [x, x, x, x, x, x, x, x, x, x]\n"
    for level in "bcdefgh":
        previous = chr(ord(level) - 1)
        text += f"{level}: &{level} [{', '.join('*' + previous for _ in range(10))}]\n"
    with pytest.raises(ConfigError, match=f"more than {MAX_ALIASES} aliases"):
        parse_yaml(text)
    assert parse_yaml("a: &a 1\nb: *a\n") == {"a": 1, "b": 1}
    exactly = "a: &a 1\n" + "".join(f"b{i}: *a\n" for i in range(MAX_ALIASES))
    assert len(parse_yaml(exactly)) == MAX_ALIASES + 1  # type: ignore[arg-type]
    with pytest.raises(ConfigError, match=f"more than {MAX_ALIASES} aliases"):
        parse_yaml(exactly + "extra: *a\n")


def test_invalid_yaml_names_the_source_and_line_without_the_content() -> None:
    with pytest.raises(ConfigError) as exc:
        parse_yaml("a: [1,\nTOPSECRET", "config.yaml")
    assert exc.value.path.startswith("config.yaml, line ") and "TOPSECRET" not in str(exc.value)


def test_the_loader_is_a_safe_loader_subclass_that_does_not_build_python_objects() -> None:
    import yaml

    assert issubclass(StrictLoader, yaml.SafeLoader)
    with pytest.raises(ConfigError):
        parse_yaml("!!python/object/apply:os.system ['true']")


def test_deadline_interrupts_a_slow_parse_in_the_main_thread_and_cleans_up() -> None:
    import signal

    previous = signal.getsignal(signal.SIGALRM)
    with pytest.raises(ConfigTimeoutError), _deadline(0.05):
        time.sleep(0.5)
    assert signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0)
    assert signal.getsignal(signal.SIGALRM) is previous
    parse_yaml("a: 1")
    assert signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0) and signal.getsignal(signal.SIGALRM) is previous


def test_deadline_gives_a_pre_existing_interval_timer_back_with_the_elapsed_time_deducted() -> None:
    import signal

    fired: list[int] = []
    previous = signal.signal(signal.SIGALRM, lambda signum, frame: fired.append(signum))
    signal.setitimer(signal.ITIMER_REAL, 30.0, 7.0)
    try:
        parse_yaml("a: 1")
        remaining, interval = signal.getitimer(signal.ITIMER_REAL)
        assert 29.0 < remaining <= 30.0 and interval == 7.0 and fired == []
        with _deadline(5.0):
            time.sleep(0.3)
        # The 0.3 s spent under our deadline must be missing from the caller's timer afterwards.
        assert 29.0 < signal.getitimer(signal.ITIMER_REAL)[0] <= remaining - 0.25
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def test_deadline_fires_a_timer_that_expired_while_it_was_suspended() -> None:
    import signal

    fired: list[int] = []
    previous = signal.signal(signal.SIGALRM, lambda signum, frame: fired.append(signum))
    signal.setitimer(signal.ITIMER_REAL, 0.05)
    try:
        with _deadline(5.0):
            time.sleep(0.1)
        deadline = time.monotonic() + 1.0
        while not fired and time.monotonic() < deadline:
            time.sleep(0.01)
        assert fired == [signal.SIGALRM]
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def test_deadline_is_a_no_op_outside_the_main_thread() -> None:
    outcome: list[str] = []

    def work() -> None:
        with _deadline(0.01):
            time.sleep(0.05)
        outcome.append("done")

    thread = threading.Thread(target=work)
    thread.start()
    thread.join()
    assert outcome == ["done"]


@pytest.mark.parametrize(
    ("text", "detail"),
    [
        ('a: !!int "TOPSECRET"', "expected an integer"),
        ('a: !!int ""', "expected an integer"),
        ('a: !!int "0xZZ"', "expected an integer"),
        ('a: !!float "TOPSECRET"', "expected a number"),
        ('a: !!float "1e9999"', "expected a finite number"),
        ('a: !!bool "TOPSECRET"', "expected true or false"),
        ('a: !!bool "yes"', "expected true or false"),
        ('a: !!timestamp "TOPSECRET"', "invalid YAML"),
        ('a: !!binary "TOPSECRET"', "invalid YAML"),
        ("a: !!set {TOPSECRET: null}", "invalid YAML"),
        ("a: !!omap [{TOPSECRET: 1}]", "invalid YAML"),
        ("a: !!pairs [{TOPSECRET: 1}]", "invalid YAML"),
        ('a: !!python/name:os.system "TOPSECRET"', "invalid YAML"),
        ('a: !custom "TOPSECRET"', "invalid YAML"),
        ('a: !!map "TOPSECRET"', "expected a mapping"),
        ("a: !!map [TOPSECRET, KEY]", "expected a mapping"),
        ("a: !!map [[TOPSECRET, KEY]]", "expected a mapping"),
        ('a: !!seq "TOPSECRET"', "invalid YAML"),
        ("a: !!str {TOPSECRET: 1}", "invalid YAML"),
        ("a: !!int [TOPSECRET]", "invalid YAML"),
    ],
)
def test_explicit_tags_outside_the_core_schema_are_refused_without_echoing_the_value(text: str, detail: str) -> None:
    with pytest.raises(ConfigError) as exc:
        parse_yaml(text + "\n")
    assert exc.value.detail == detail and "TOPSECRET" not in str(exc.value) and "topsecret" not in str(exc.value)


def test_yaml_11_merge_and_value_indicators_stay_strings() -> None:
    assert parse_yaml("password: =\n<<: x\nb: '<<'\n") == {"password": "=", "<<": "x", "b": "<<"}


def test_explicit_core_tags_still_work() -> None:
    assert parse_yaml('a: !!str 12\nb: !!int "0x1f"\nc: !!float "2"\nd: !!bool "true"\ne: !!null "x"\n') == {
        "a": "12", "b": 31, "c": 2.0, "d": True, "e": None,
    }  # fmt: skip
