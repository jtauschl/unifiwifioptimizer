"""Questions to the person at the terminal. They go to stderr, so a redirected report stays a report, and the
answer is read from stdin; without terminals on both the answer is "no", said with its warning lines and the
non-interactive way to answer."""

import sys

from unifiwifioptimizer.app.trust import Prompt
from unifiwifioptimizer.domain.commands import PROGRAM
from unifiwifioptimizer.report.safe_text import safe_text

MAX_PROMPT_CHARS = 2048
FINGERPRINT_PREFIX_CHARS = 8


def can_ask() -> bool:
    return sys.stdin.isatty() and sys.stderr.isatty()


def terminal_confirm(prompt: Prompt) -> bool:
    """`y/N` where the tool verified the new key itself. Where the person is the only check, or a stored key is
    overwritten (`prompt.kind.typed_answer`), the first characters of the new key's SHA-256 must be typed after the
    warning lines: a guard against answering by routine, not a verification. EOF (Ctrl-D) and anything else is a
    decline."""
    text = safe_text(prompt.text, max_chars=MAX_PROMPT_CHARS)
    warning = [safe_text(line, max_chars=MAX_PROMPT_CHARS) for line in prompt.warning]
    if not can_ask():
        print(f"{PROGRAM}: {text} — no terminal to ask; declined", file=sys.stderr)
        for line in warning:
            print(f"{PROGRAM}: {line}", file=sys.stderr)
        print(f"{PROGRAM}: {safe_text(prompt.unattended, max_chars=MAX_PROMPT_CHARS)}", file=sys.stderr)
        return False
    for line in warning:
        sys.stderr.write(f"{line}\n")
    if not prompt.kind.typed_answer:
        sys.stderr.write(f"{text} [y/N] ")
        sys.stderr.flush()
        return sys.stdin.readline().strip().lower() in ("y", "yes")
    expected = prompt.new_fingerprint.removeprefix("SHA256:")[:FINGERPRINT_PREFIX_CHARS]
    sys.stderr.write(
        f"{text}\nType the first {FINGERPRINT_PREFIX_CHARS} characters of the new key after SHA256: "
        f"({safe_text(expected, max_chars=MAX_PROMPT_CHARS)}) to {prompt.kind.action} it, anything else declines: "
    )
    sys.stderr.flush()
    return sys.stdin.readline().strip() == expected
