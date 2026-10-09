"""Process exit codes.

Every value is part of the public contract: scripts wrapping the tool branch on them, so a value is
never renumbered.
"""

from enum import IntEnum


class ExitCode(IntEnum):
    OK = 0
    UNEXPECTED_ERROR = 1
    USAGE = 2
    CONFIG = 3
    TLS = 4
    HOST_KEY = 5
    PARTIAL = 6
    ENVIRONMENT = 7
    INTERRUPTED = 130
