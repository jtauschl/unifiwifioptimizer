"""The terminal prompt: stderr only, `y/N` for a new key, the typed fingerprint prefix for a replace, no terminal
and EOF are a "no", and nothing from the controller reaches the terminal unescaped."""

import io

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
    return Prompt(kind=PromptKind.NEW, text=text, new_fingerprint=FINGERPRINT)


def replace() -> Prompt:
    return Prompt(kind=PromptKind.REPLACE, text="default: AP-1: replace it?", new_fingerprint=FINGERPRINT)


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
@pytest.mark.parametrize("kind", [PromptKind.NEW, PromptKind.REPLACE])
def test_without_both_terminals_the_answer_is_no_and_nothing_is_read(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], kind: PromptKind
) -> None:
    stdin = io.StringIO("y\n")
    monkeypatch.setattr("sys.stdin", stdin)
    assert terminal_confirm(Prompt(kind=kind, text="AP-1: store?", new_fingerprint=FINGERPRINT)) is False
    assert stdin.tell() == 0
    assert "no terminal to ask; declined" in capsys.readouterr().err


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
