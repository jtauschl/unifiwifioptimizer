"""Resume decisions of the release workflow, standard library only.

A release publishes to PyPI and then to GitHub, and each step uploads file by file, so a failed run can
leave one file behind. Re-running must neither fail on that file nor replace it with different bytes. This
module asks the remote what it holds right now, compares that with what the build produced and says what is
still missing, or refuses when the remote holds something that differs. It also checks that a downloaded
artifact directory holds exactly the hashed files, so a job never acts on a file nobody hashed.

The privileged jobs have no checkout: they download this single file as a hash-checked artifact and run it
with `python3 -I`, so it imports nothing from the repository. Results are `key=value` lines for
`$GITHUB_OUTPUT`; every value is restricted to a character set that cannot start a new line or a new key.
"""

import argparse
import hashlib
import http.client
import json
import os
import re
import shutil
import sys
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

ALLOWED_HOSTS = frozenset({"pypi.org", "api.github.com"})
MAX_RESPONSE_BYTES = 8 * 1024 * 1024
TIMEOUT_S = 15.0
MAX_RELEASE_PAGES = 10
SHA256 = re.compile(r"[0-9a-f]{64}")
FILENAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,200}")
PROJECT = re.compile(r"[a-z0-9][a-z0-9._-]{0,100}")
VERSION = re.compile(r"[0-9A-Za-z][0-9A-Za-z.+!_-]{0,100}")
REPOSITORY = re.compile(r"[A-Za-z0-9._-]+/[A-Za-z0-9._-]+")
TAG = re.compile(r"v[0-9A-Za-z.+_-]{1,100}")

Fetch = Callable[[str, str, Mapping[str, str]], tuple[int, bytes]]
Sleep = Callable[[float], None]


class ReleaseGuardError(Exception):
    """The remote and the build disagree, or the remote could not be read; the run must stop."""


class State(StrEnum):
    ABSENT = "absent"
    PARTIAL = "partial"
    COMPLETE = "complete"


@dataclass(frozen=True, slots=True)
class Reconciliation:
    state: State
    missing: tuple[str, ...]


def https_get(host: str, path: str, headers: Mapping[str, str]) -> tuple[int, bytes]:
    """One verified GET to an allow-listed host; redirects and oversized bodies are errors."""
    if host not in ALLOWED_HOSTS:
        raise ReleaseGuardError(f"refusing to contact {host}")
    # The default context verifies certificate and hostname; the audit rule only flags the class.
    # nosemgrep: python.lang.security.audit.httpsconnection-detected.httpsconnection-detected
    connection = http.client.HTTPSConnection(host, timeout=TIMEOUT_S)
    try:
        connection.request("GET", path, headers=dict(headers))
        response = connection.getresponse()
        if 300 <= response.status < 400:
            raise ReleaseGuardError(f"{host}{path}: redirect refused (status {response.status})")
        body = response.read(MAX_RESPONSE_BYTES + 1)
        if len(body) > MAX_RESPONSE_BYTES:
            raise ReleaseGuardError(f"{host}{path}: response larger than {MAX_RESPONSE_BYTES} bytes")
        return response.status, body
    except (OSError, http.client.HTTPException) as error:
        raise ReleaseGuardError(f"{host}{path}: {type(error).__name__}: {error}") from None
    finally:
        connection.close()


def _listing(names: Sequence[str], limit: int = 5) -> str:
    shown = ", ".join(names[:limit])
    return shown if len(names) <= limit else f"{shown} and {len(names) - limit} more"


def parse_hashes(text: str) -> dict[str, str]:
    """`sha256sum` output (`<hex>  <name>`) as {name: hex}; anything else is an error."""
    wanted: dict[str, str] = {}
    for line in text.splitlines():
        if not line.strip():
            continue
        digest, separator, name = line.partition("  ")
        if not separator or not SHA256.fullmatch(digest) or not FILENAME.fullmatch(name):
            raise ReleaseGuardError(f"not a sha256sum line: {line[:80]!r}")
        if name in wanted:
            raise ReleaseGuardError(f"{name} is listed twice")
        wanted[name] = digest
    if not wanted:
        raise ReleaseGuardError("the hash list is empty")
    return wanted


def reconcile(existing: Mapping[str, str], wanted: Mapping[str, str]) -> Reconciliation:
    """What a re-run still has to upload; a file that is extra or differs on the remote is an error."""
    extra = sorted(set(existing) - set(wanted))
    if extra:
        raise ReleaseGuardError(f"the remote holds files this build did not produce: {_listing(extra)}")
    differing = sorted(name for name in existing if existing[name] != wanted[name])
    if differing:
        raise ReleaseGuardError(f"the remote holds different bytes for: {_listing(differing)}")
    missing = tuple(sorted(set(wanted) - set(existing)))
    if not existing:
        return Reconciliation(State.ABSENT, missing)
    return Reconciliation(State.PARTIAL if missing else State.COMPLETE, missing)


def _json(body: bytes, where: str) -> object:
    try:
        return json.loads(body)
    except ValueError:
        raise ReleaseGuardError(f"{where}: the response is not JSON") from None


def pypi_files(fetch: Fetch, project: str, version: str) -> dict[str, str]:
    if not PROJECT.fullmatch(project) or not VERSION.fullmatch(version):
        raise ReleaseGuardError("project or version is not a plain name")
    status, body = fetch("pypi.org", f"/pypi/{project}/{version}/json", {"Accept": "application/json"})
    if status == 404:
        return {}
    if status != 200:
        raise ReleaseGuardError(f"PyPI answered {status} for {project} {version}")
    document = _json(body, "PyPI")
    try:
        if not isinstance(document, dict):
            raise TypeError
        return {str(entry["filename"]): str(entry["digests"]["sha256"]) for entry in document["urls"]}
    except (KeyError, TypeError):
        raise ReleaseGuardError("PyPI: unexpected response shape") from None


def release_assets(fetch: Fetch, repository: str, tag: str, token: str) -> tuple[str, dict[str, str]] | None:
    """("draft" | "published", {asset: sha256}) of the release for `tag`, or None when there is none."""
    if not REPOSITORY.fullmatch(repository) or not TAG.fullmatch(tag):
        raise ReleaseGuardError("repository or tag is not a plain name")
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "unifiwifioptimizer-release",
    }
    matches: list[tuple[str, dict[str, str]]] = []
    for page in range(1, MAX_RELEASE_PAGES + 1):
        status, body = fetch("api.github.com", f"/repos/{repository}/releases?per_page=100&page={page}", headers)
        if status != 200:
            raise ReleaseGuardError(f"GitHub answered {status} for the release list of {repository}")
        releases = _json(body, "GitHub")
        if not isinstance(releases, list):
            raise ReleaseGuardError("GitHub: unexpected response shape")
        if not releases:
            break
        for release in releases:
            try:
                if release["tag_name"] == tag:
                    assets = {str(asset["name"]): _asset_digest(asset) for asset in release["assets"]}
                    matches.append((("draft" if release["draft"] else "published"), assets))
            except (KeyError, TypeError):
                raise ReleaseGuardError("GitHub: unexpected release shape") from None
    else:
        raise ReleaseGuardError(f"the release list of {repository} exceeds {MAX_RELEASE_PAGES} pages")
    if len(matches) > 1:
        raise ReleaseGuardError(f"{len(matches)} releases share the tag {tag}; resolve that by hand")
    return matches[0] if matches else None


def _asset_digest(asset: Mapping[str, object]) -> str:
    digest = str(asset.get("digest") or "")
    algorithm, _, value = digest.partition(":")
    if algorithm != "sha256" or not SHA256.fullmatch(value):
        raise ReleaseGuardError(f"release asset {asset.get('name')!s} carries no sha256 digest")
    return value


def verify_dir(directory: Path, wanted: Mapping[str, str]) -> None:
    """The directory holds exactly the listed files, each with the listed bytes; nothing else, no links."""
    found = sorted(entry.name for entry in directory.iterdir())
    if found != sorted(wanted):
        raise ReleaseGuardError(f"{directory} holds {_listing(found)}, expected {_listing(sorted(wanted))}")
    for name, digest in wanted.items():
        path = directory / name
        if path.is_symlink() or not path.is_file():
            raise ReleaseGuardError(f"{path} is not a regular file")
        if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise ReleaseGuardError(f"{path} does not have the hashed bytes")


def select_upload(dist: Path, wanted: Mapping[str, str], missing: Sequence[str], out: Path) -> int:
    """Copy exactly the missing files, each verified against the build's hash, into a fresh directory."""
    out.mkdir(parents=True, exist_ok=False)
    for name in missing:
        if name not in wanted:
            raise ReleaseGuardError(f"{name} is not a file of this build")
        source = dist / name
        if hashlib.sha256(source.read_bytes()).hexdigest() != wanted[name]:
            raise ReleaseGuardError(f"{name} changed since it was hashed")
        shutil.copy2(source, out / name)
    return len(missing)


def _emit(result: Reconciliation, **extra: str) -> None:
    for key, value in extra.items():
        print(f"{key}={value}")
    print(f"state={result.state}")
    print(f"missing={' '.join(result.missing)}")


def run(args: argparse.Namespace, fetch: Fetch, sleep: Sleep) -> int:
    wanted = parse_hashes(Path(args.hashes).read_text(encoding="utf-8"))
    if args.command == "pypi-state":
        _emit(reconcile(pypi_files(fetch, args.project, args.version), wanted))
    elif args.command == "pypi-verify":
        result = reconcile(pypi_files(fetch, args.project, args.version), wanted)
        for _ in range(args.attempts - 1):
            if result.state is State.COMPLETE:
                break
            sleep(args.delay)
            result = reconcile(pypi_files(fetch, args.project, args.version), wanted)
        if result.state is not State.COMPLETE:
            raise ReleaseGuardError(f"PyPI lacks: {' '.join(result.missing)}")
    elif args.command == "release-state":
        token = os.environ.get("GH_TOKEN", "")
        if not token:
            raise ReleaseGuardError("GH_TOKEN is not set")
        existing = release_assets(fetch, args.repository, args.tag, token)
        kind, assets = existing if existing is not None else ("absent", {})
        _emit(reconcile(assets, wanted), release=kind)
    elif args.command == "verify-dir":
        verify_dir(Path(args.dir), wanted)
    else:
        missing = reconcile(pypi_files(fetch, args.project, args.version), wanted).missing
        print(f"count={select_upload(Path(args.dist), wanted, missing, Path(args.out))}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("pypi-state", "pypi-verify"):
        sub = commands.add_parser(name)
        sub.add_argument("--project", required=True)
        sub.add_argument("--version", required=True)
        sub.add_argument("--hashes", required=True)
        if name == "pypi-verify":
            sub.add_argument("--attempts", type=int, default=6)
            sub.add_argument("--delay", type=float, default=20.0)
    release = commands.add_parser("release-state")
    release.add_argument("--repository", required=True)
    release.add_argument("--tag", required=True)
    release.add_argument("--hashes", required=True)
    select = commands.add_parser("select-upload")
    select.add_argument("--dist", required=True)
    select.add_argument("--hashes", required=True)
    select.add_argument("--project", required=True)
    select.add_argument("--version", required=True)
    select.add_argument("--out", required=True)
    verify = commands.add_parser("verify-dir")
    verify.add_argument("--dir", required=True)
    verify.add_argument("--hashes", required=True)
    return parser


def main(argv: Sequence[str] | None = None, fetch: Fetch = https_get, sleep: Sleep = time.sleep) -> int:
    args = build_parser().parse_args(argv)
    try:
        return run(args, fetch, sleep)
    except (ReleaseGuardError, OSError) as error:
        print(f"release_guard: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
