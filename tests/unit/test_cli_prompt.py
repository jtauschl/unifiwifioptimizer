"""The terminal prompt: stderr only, `y/N` for a new key the tool verified, the typed fingerprint prefix for a key on
no basis and for every replace, no terminal and EOF are a "no", and nothing from the controller reaches the terminal
unescaped."""

import io
from collections.abc import Callable

import pytest

from unifiwifioptimizer.app.trust import Prompt, PromptKind
from unifiwifioptimizer.cli import prompt as prompt_module
from unifiwifioptimizer.cli.prompt import terminal_confirm

FINGERPRINT = "SHA256:abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG"
PREFIX = "abcdefgh"


class Terminal(io.StringIO):
    def isatty(self) -> bool:
        return True


def wire(monkeypatch: pytest.MonkeyPatch, answer: str, *, tty: bool = True) -> io.StringIO:
    stdin, stderr = io.StringIO(answer), io.StringIO()
    if tty:
        stdin, stderr = Terminal(answer), Terminal()
    monkeypatch.setattr("sys.stdin", stdin)
    monkeypatch.setattr("sys.stderr", stderr)
    return stderr


def new(text: str = "default: AP-1: store host key?") -> Prompt:
    return Prompt(
        kind=PromptKind.NEW,
        text=text,
        new_fingerprint=FINGERPRINT,
        unattended="to store it without asking, add to the command: --yes",
    )


def replace() -> Prompt:
    return Prompt(
        kind=PromptKind.REPLACE,
        text="default: AP-1: replace it?",
        new_fingerprint=FINGERPRINT,
        unattended="a changed key on no basis needs a terminal to be replaced",
    )


WARNING = (
    "access point AP-1, MAC 02:00:00:00:00:01, address 192.168.1.2",
    "neither a pin nor the controller verifies this key",
)


def unverified() -> Prompt:
    return Prompt(
        kind=PromptKind.NEW_UNVERIFIED,
        text="default: AP-1: store host key on first use?",
        new_fingerprint=FINGERPRINT,
        warning=WARNING,
        unattended="to store it without asking, add to the command: --ap=AP-1 --accept-unverified",
    )


@pytest.mark.security("T8")
@pytest.mark.parametrize(
    ("answer", "accepted"), [("y\n", True), ("YES\n", True), ("n\n", False), ("\n", False), ("", False)]
)
def test_a_new_key_needs_a_yes_and_eof_is_a_no(monkeypatch: pytest.MonkeyPatch, answer: str, accepted: bool) -> None:
    err = wire(monkeypatch, answer)
    assert terminal_confirm(new()) is accepted
    assert err.getvalue() == "default: AP-1: store host key? [y/N] "


@pytest.mark.security("T8")
@pytest.mark.parametrize(
    ("answer", "accepted"),
    [(f"{PREFIX}\n", True), (f"  {PREFIX}  \n", True), ("y\n", False), ("yes\n", False), (f"{PREFIX.upper()}\n", False),
     (f"{PREFIX[:-1]}\n", False), ("", False)],
)  # fmt: skip
def test_a_replace_needs_the_fingerprint_prefix_typed_exactly(
    monkeypatch: pytest.MonkeyPatch, answer: str, accepted: bool
) -> None:
    err = wire(monkeypatch, answer)
    assert terminal_confirm(replace()) is accepted
    assert PREFIX in err.getvalue() and "replace it?" in err.getvalue()


@pytest.mark.security("T8")
@pytest.mark.parametrize(
    ("answer", "accepted"),
    [(f"{PREFIX}\n", True), (f"  {PREFIX}  \n", True), ("y\n", False), ("yes\n", False), ("Y\n", False),
     (f"{PREFIX.upper()}\n", False), (f"{PREFIX[:-1]}\n", False), ("", False)],
)  # fmt: skip
def test_a_new_key_on_no_basis_needs_the_fingerprint_prefix_typed_exactly_after_the_warning_lines(
    monkeypatch: pytest.MonkeyPatch, answer: str, accepted: bool
) -> None:
    err = wire(monkeypatch, answer)
    assert terminal_confirm(unverified()) is accepted
    assert err.getvalue() == (
        "access point AP-1, MAC 02:00:00:00:00:01, address 192.168.1.2\n"
        "neither a pin nor the controller verifies this key\n"
        "default: AP-1: store host key on first use?\n"
        f"Type the first 8 characters of the new key after SHA256: ({PREFIX}) to store it, anything else declines: "
    )


@pytest.mark.security("T8")
def test_a_replace_names_the_action_in_the_instruction(monkeypatch: pytest.MonkeyPatch) -> None:
    err = wire(monkeypatch, "")
    terminal_confirm(replace())
    assert err.getvalue().endswith(f"({PREFIX}) to replace it, anything else declines: ")


@pytest.mark.security("T8")
@pytest.mark.parametrize("prompt_for", [new, replace, unverified], ids=["new-verified", "replace", "new-unverified"])
def test_without_both_terminals_the_answer_is_no_and_nothing_is_read(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], prompt_for: Callable[[], Prompt]
) -> None:
    stdin = io.StringIO("y\n")
    monkeypatch.setattr("sys.stdin", stdin)
    assert terminal_confirm(prompt_for()) is False
    assert stdin.tell() == 0
    assert "no terminal to ask; declined" in capsys.readouterr().err


@pytest.mark.security("T8")
def test_the_decline_without_a_terminal_prints_the_warning_lines_and_the_way_to_answer_unattended(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr("sys.stdin", io.StringIO(""))
    assert terminal_confirm(unverified()) is False
    assert capsys.readouterr().err.splitlines() == [
        "unifiwifioptimizer: default: AP-1: store host key on first use? — no terminal to ask; declined",
        "unifiwifioptimizer: access point AP-1, MAC 02:00:00:00:00:01, address 192.168.1.2",
        "unifiwifioptimizer: neither a pin nor the controller verifies this key",
        "unifiwifioptimizer: to store it without asking, add to the command: --ap=AP-1 --accept-unverified",
    ]


def test_a_terminal_on_stdin_alone_is_not_enough(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("sys.stdin", Terminal("y\n"))
    monkeypatch.setattr("sys.stderr", io.StringIO())
    assert prompt_module.can_ask() is False
    monkeypatch.setattr("sys.stdin", io.StringIO("y\n"))
    monkeypatch.setattr("sys.stderr", Terminal())
    assert prompt_module.can_ask() is False


@pytest.mark.security("T12")
def test_controller_strings_are_escaped_in_the_question(monkeypatch: pytest.MonkeyPatch) -> None:
    err = wire(monkeypatch, "n\n")
    terminal_confirm(new("default: AP\x1b[2J: store?"))
    assert "\x1b" not in err.getvalue()


@pytest.mark.security("T12")
def test_a_control_character_in_a_warning_line_or_the_hint_cannot_break_out_of_its_line(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    hostile = Prompt(
        kind=PromptKind.NEW_UNVERIFIED,
        text="AP\x1b[2J: store?",
        new_fingerprint=FINGERPRINT,
        warning=("access point A\nforged line, MAC x\x1b[31m",),
        unattended="add to the command: --ap='A\nB'\x1b[31m",
    )
    err = wire(monkeypatch, "n\n")
    terminal_confirm(hostile)
    assert err.getvalue().splitlines()[0] == "access point A" + "\ufffd" + "forged line, MAC x"
    declined = wire(monkeypatch, "", tty=False)
    terminal_confirm(hostile)
    assert declined.getvalue().splitlines() == [
        "unifiwifioptimizer: AP: store? — no terminal to ask; declined",
        f"unifiwifioptimizer: access point A{chr(0xFFFD)}forged line, MAC x",
        f"unifiwifioptimizer: add to the command: --ap='A{chr(0xFFFD)}B'",
    ]
