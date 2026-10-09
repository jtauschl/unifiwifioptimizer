"""Error hierarchy shared by every layer.

Each subclass names one failure class; the command line decides the exit code. A message is written
for the operator and never embeds secrets or raw external strings.
"""


class UwoError(Exception):
    """Base class for every error the tool raises on purpose."""


class NotImplementedPathError(UwoError):
    """A code path that exists in the interface but has no implementation in this build."""

    def __init__(self, path: str) -> None:
        super().__init__(f"{path} is not implemented in this build")
        self.path = path
