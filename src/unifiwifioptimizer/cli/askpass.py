"""`SSH_ASKPASS` helper: hands OpenSSH the password from the child's environment, nothing else.

OpenSSH runs this program with the prompt as its only argument and reads one line from its stdout. The
password never appears in any argv: the scanner puts it into this child's environment only, and
`SSH_ASKPASS_REQUIRE=force` makes OpenSSH ask here instead of at a terminal.
"""

import os
import sys

PASSWORD_ENV = "UWO_SSH_PASSWORD"  # noqa: S105 # nosec B105 — the name of a variable, not a credential


def main() -> int:
    password = os.environ.get(PASSWORD_ENV)
    if password is None:
        print(f"unifiwifioptimizer-askpass: {PASSWORD_ENV} is not set", file=sys.stderr)
        return 1
    sys.stdout.write(password + "\n")
    sys.stdout.flush()
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
