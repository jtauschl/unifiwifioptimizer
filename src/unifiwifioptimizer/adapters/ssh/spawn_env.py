"""The environment every OpenSSH child process starts from: an allow-list, never the parent's environment."""

from collections.abc import Mapping

DEFAULT_PATH = "/usr/bin:/bin"


def base_child_env(environ: Mapping[str, str]) -> dict[str, str]:
    """`PATH` as the caller resolved it (so `ssh -V`, `ssh` and `ssh-keyscan` find the same binaries) and a C
    locale for parseable output; everything else a child needs is added by its own spawn site."""
    return {"PATH": environ.get("PATH", DEFAULT_PATH), "LC_ALL": "C"}
