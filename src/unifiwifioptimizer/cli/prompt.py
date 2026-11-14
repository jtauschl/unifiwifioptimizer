"""Questions to the person at the terminal. They go to stderr, so a redirected report stays a report, and the
answer is read from stdin; without terminals on both the answer is "no"."""

import sys

from unifiwifioptimizer.app.trust import Prompt, PromptKind
from unifiwifioptimizer.report.safe_text import safe_text

MAX_PROMPT_CHARS = 2048
FINGERPRINT_PREFIX_CHARS = 8
_PROGRAM = "unifiwifioptimizer"


def can_ask() -> bool:
    return sys.stdin.isatty() and sys.stderr.isatty()


def terminal_confirm(prompt: Prompt) -> bool:
    """`y/N` for a new key. A replace needs the first characters of the new key's SHA-256 typed: a guard
    against answering by routine, not a verification. EOF (Ctrl-D) and anything else is a decline."""
    text = safe_text(prompt.text, max_chars=MAX_PROMPT_CHARS)
    if not can_ask():
        print(f"{_PROGRAM}: {text} — no terminal to ask; declined", file=sys.stderr)
        return False
    if prompt.kind is PromptKind.NEW:
        sys.stderr.write(f"{text} [y/N] ")
        sys.stderr.flush()
        return sys.stdin.readline().strip().lower() in ("y", "yes")
    expected = prompt.new_fingerprint.removeprefix("SHA256:")[:FINGERPRINT_PREFIX_CHARS]
    sys.stderr.write(
        f"{text}\nType the first {FINGERPRINT_PREFIX_CHARS} characters of the new key after SHA256: "
        f"({safe_text(expected, max_chars=MAX_PROMPT_CHARS)}) to replace it, anything else declines: "
    )
    sys.stderr.flush()
    return sys.stdin.readline().strip() == expected
