"""The release workflow's resume decisions: what a re-run uploads, and when it must stop instead."""

import hashlib
import http.client
import json
import re
from collections.abc import Mapping
from pathlib import Path

import pytest

from tests.unit.scripts import load_script

guard = load_script("release_guard")

WHEEL = "unifiwifioptimizer-0.5.0-py3-none-any.whl"
SDIST = "unifiwifioptimizer-0.5.0.tar.gz"
SBOM = "sbom.cdx.json"
A, B, C = "a" * 64, "b" * 64, "c" * 64
WANTED = {WHEEL: A, SDIST: B}
TOKEN = "ghs_token-that-must-never-be-printed"


def hashes_file(tmp_path: Path, wanted: Mapping[str, str] = WANTED) -> Path:
    path = tmp_path / "hashes.txt"
    path.write_text("".join(f"{digest}  {name}\n" for name, digest in wanted.items()), encoding="utf-8")
    return path


class FakeRemote:
    """Answers `fetch` from a table of (host, path-prefix) -> (status, JSON document) and records calls."""

    def __init__(self, *answers: tuple[str, str, int, object]) -> None:
        self.answers = list(answers)
        self.calls: list[tuple[str, str, Mapping[str, str]]] = []

    def __call__(self, host: str, path: str, headers: Mapping[str, str]) -> tuple[int, bytes]:
        self.calls.append((host, path, headers))
        for wanted_host, prefix, status, document in self.answers:
            if host == wanted_host and path.startswith(prefix):
                body = document if isinstance(document, bytes) else json.dumps(document).encode()
                return status, body
        raise AssertionError(f"unexpected request {host}{path}")


def pypi(files: Mapping[str, str]) -> tuple[str, str, int, object]:
    urls = [{"filename": name, "digests": {"sha256": digest}} for name, digest in files.items()]
    return "pypi.org", "/pypi/unifiwifioptimizer/0.5.0/json", 200, {"urls": urls}


def release(tag: str, assets: Mapping[str, str | None], *, draft: bool = False) -> dict[str, object]:
    return {
        "tag_name": tag,
        "draft": draft,
        "assets": [{"name": n, "digest": None if d is None else f"sha256:{d}"} for n, d in assets.items()],
    }


def release_pages(*releases: dict[str, object]) -> list[tuple[str, str, int, object]]:
    return [
        ("api.github.com", "/repos/o/r/releases?per_page=100&page=1", 200, list(releases)),
        ("api.github.com", "/repos/o/r/releases?per_page=100&page=2", 200, []),
    ]


# --- reconcile -------------------------------------------------------------------------------------------


def test_nothing_on_the_remote_means_everything_is_missing() -> None:
    result = guard.reconcile({}, WANTED)
    assert result.state is guard.State.ABSENT and result.missing == tuple(sorted(WANTED))


def test_a_subset_with_equal_bytes_is_partial_and_names_only_the_rest() -> None:
    result = guard.reconcile({WHEEL: A}, WANTED)
    assert result.state is guard.State.PARTIAL and result.missing == (SDIST,)


def test_everything_present_and_equal_is_complete() -> None:
    result = guard.reconcile(dict(WANTED), WANTED)
    assert result.state is guard.State.COMPLETE and result.missing == ()


def test_different_bytes_on_the_remote_are_an_error_never_an_overwrite() -> None:
    with pytest.raises(guard.ReleaseGuardError, match="different bytes for: " + WHEEL):
        guard.reconcile({WHEEL: C}, WANTED)


def test_a_file_this_build_did_not_produce_is_an_error() -> None:
    with pytest.raises(guard.ReleaseGuardError, match=re.escape("did not produce: stray.whl")):
        guard.reconcile({"stray.whl": A}, WANTED)


# --- parse_hashes ----------------------------------------------------------------------------------------


def test_sha256sum_output_is_parsed_into_names_and_digests() -> None:
    assert guard.parse_hashes(f"{A}  {WHEEL}\n\n{B}  {SDIST}\n") == WANTED


@pytest.mark.parametrize(
    "text",
    [
        "",
        f"{A[:-1]}  {WHEEL}\n",
        f"{A.upper()}  {WHEEL}\n",
        f"{A} {WHEEL}\n",
        f"{A}  ../{WHEEL}\n",
        f"{A}  dir/{WHEEL}\n",
        f"{A}  {WHEEL}\n{B}  {WHEEL}\n",
        f"{A}  {WHEEL}\nmissing=injected\n",
    ],
    ids=["empty", "short", "upper", "one-space", "dotdot", "subdir", "duplicate", "stray-line"],
)
def test_a_malformed_hash_list_is_refused(text: str) -> None:
    with pytest.raises(guard.ReleaseGuardError):
        guard.parse_hashes(text)


# --- PyPI ------------------------------------------------------------------------------------------------


def test_pypi_files_reads_names_and_sha256_digests() -> None:
    assert guard.pypi_files(FakeRemote(pypi(WANTED)), "unifiwifioptimizer", "0.5.0") == WANTED


def test_an_unknown_version_is_an_empty_set_not_an_error() -> None:
    remote = FakeRemote(("pypi.org", "/pypi/", 404, {}))
    assert guard.pypi_files(remote, "unifiwifioptimizer", "0.5.0") == {}


@pytest.mark.parametrize(
    "answer",
    [(500, {}), (200, b"<html>"), (200, ["not", "a", "dict"]), (200, {"urls": [{"filename": "x"}]}), (200, {})],
    ids=["server-error", "not-json", "wrong-type", "missing-digest", "missing-urls"],
)
def test_an_unreadable_pypi_answer_stops_the_run(answer: tuple[int, object]) -> None:
    remote = FakeRemote(("pypi.org", "/pypi/", *answer))
    with pytest.raises(guard.ReleaseGuardError):
        guard.pypi_files(remote, "unifiwifioptimizer", "0.5.0")


@pytest.mark.parametrize(("project", "version"), [("a/b", "0.5.0"), ("unifiwifioptimizer", "0.5.0/../x"), ("", "1")])
def test_project_and_version_are_plain_names_before_they_reach_a_url(project: str, version: str) -> None:
    remote = FakeRemote()
    with pytest.raises(guard.ReleaseGuardError, match="plain name"):
        guard.pypi_files(remote, project, version)
    assert remote.calls == []


# --- GitHub release --------------------------------------------------------------------------------------


def test_no_release_for_the_tag_is_none() -> None:
    remote = FakeRemote(
        ("api.github.com", "/repos/o/r/releases?per_page=100&page=1", 200, [release("v0.4.0", {})]),
        ("api.github.com", "/repos/o/r/releases?per_page=100&page=2", 200, []),
    )
    assert guard.release_assets(remote, "o/r", "v0.5.0", TOKEN) is None


def test_the_release_is_found_on_a_later_page_and_its_digests_are_read() -> None:
    remote = FakeRemote(
        ("api.github.com", "/repos/o/r/releases?per_page=100&page=1", 200, [release("v0.4.0", {})]),
        ("api.github.com", "/repos/o/r/releases?per_page=100&page=2", 200, [release("v0.5.0", {WHEEL: A, SBOM: C})]),
        ("api.github.com", "/repos/o/r/releases?per_page=100&page=3", 200, []),
    )
    assert guard.release_assets(remote, "o/r", "v0.5.0", TOKEN) == ("published", {WHEEL: A, SBOM: C})


def test_a_release_without_assets_exists_with_an_empty_set() -> None:
    remote = FakeRemote(*release_pages(release("v0.5.0", {})))
    assert guard.release_assets(remote, "o/r", "v0.5.0", TOKEN) == ("published", {})


def test_a_draft_is_reported_as_a_draft_with_the_assets_already_attached() -> None:
    remote = FakeRemote(*release_pages(release("v0.5.0", {WHEEL: A}, draft=True)))
    assert guard.release_assets(remote, "o/r", "v0.5.0", TOKEN) == ("draft", {WHEEL: A})


def test_two_releases_for_one_tag_are_an_error_because_gh_and_the_helper_could_pick_different_ones() -> None:
    remote = FakeRemote(*release_pages(release("v0.5.0", {WHEEL: A}, draft=True), release("v0.5.0", {WHEEL: A})))
    with pytest.raises(guard.ReleaseGuardError, match=re.escape("2 releases share the tag v0.5.0")):
        guard.release_assets(remote, "o/r", "v0.5.0", TOKEN)


def test_a_release_list_that_never_ends_is_an_error_not_a_guess() -> None:
    pages = [
        ("api.github.com", f"/repos/o/r/releases?per_page=100&page={n}", 200, [release("v0.1.0", {})])
        for n in range(1, guard.MAX_RELEASE_PAGES + 1)
    ]
    with pytest.raises(guard.ReleaseGuardError, match="exceeds"):
        guard.release_assets(FakeRemote(*pages), "o/r", "v0.5.0", TOKEN)


def test_an_asset_without_a_sha256_digest_cannot_be_compared_and_is_an_error() -> None:
    remote = FakeRemote(*release_pages(release("v0.5.0", {WHEEL: None})))
    with pytest.raises(guard.ReleaseGuardError, match="no sha256 digest"):
        guard.release_assets(remote, "o/r", "v0.5.0", TOKEN)


def test_the_token_travels_only_in_the_authorization_header() -> None:
    remote = FakeRemote(("api.github.com", "/repos/o/r/releases", 200, []))
    guard.release_assets(remote, "o/r", "v0.5.0", TOKEN)
    (_, path, headers) = remote.calls[0]
    assert headers["Authorization"] == f"Bearer {TOKEN}" and TOKEN not in path


@pytest.mark.parametrize(("repository", "tag"), [("o", "v1"), ("o/r/x", "v1"), ("o/r", "1.0"), ("o/r", "v1;rm")])
def test_repository_and_tag_are_plain_names(repository: str, tag: str) -> None:
    with pytest.raises(guard.ReleaseGuardError, match="plain name"):
        guard.release_assets(FakeRemote(), repository, tag, TOKEN)


# --- the HTTP layer --------------------------------------------------------------------------------------


class FakeConnection:
    def __init__(self, status: int = 200, body: bytes = b"{}", error: Exception | None = None) -> None:
        self.status, self.body, self.error = status, body, error
        self.requested: list[tuple[str, str, dict[str, str]]] = []
        self.closed = False

    def request(self, method: str, path: str, headers: dict[str, str]) -> None:
        self.requested.append((method, path, headers))
        if self.error:
            raise self.error

    def getresponse(self) -> "FakeConnection":
        return self

    def read(self, amount: int) -> bytes:
        return self.body[:amount]

    def close(self) -> None:
        self.closed = True


def patch_connection(monkeypatch: pytest.MonkeyPatch, connection: FakeConnection) -> list[str]:
    hosts: list[str] = []

    def make(host: str, timeout: float) -> FakeConnection:
        assert timeout == guard.TIMEOUT_S
        hosts.append(host)
        return connection

    monkeypatch.setattr(http.client, "HTTPSConnection", make)
    return hosts


def test_a_host_outside_the_allow_list_is_never_contacted(monkeypatch: pytest.MonkeyPatch) -> None:
    hosts = patch_connection(monkeypatch, FakeConnection())
    with pytest.raises(guard.ReleaseGuardError, match=re.escape("refusing to contact evil.example")):
        guard.https_get("evil.example", "/", {})
    assert hosts == []


def test_a_redirect_is_refused_and_the_connection_is_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    connection = FakeConnection(status=302)
    patch_connection(monkeypatch, connection)
    with pytest.raises(guard.ReleaseGuardError, match="redirect refused"):
        guard.https_get("pypi.org", "/pypi/x/1/json", {})
    assert connection.closed


def test_an_oversized_body_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    patch_connection(monkeypatch, FakeConnection(body=b"x" * (guard.MAX_RESPONSE_BYTES + 5)))
    with pytest.raises(guard.ReleaseGuardError, match="larger than"):
        guard.https_get("pypi.org", "/pypi/x/1/json", {})


def test_a_transport_error_does_not_repeat_the_request_headers(monkeypatch: pytest.MonkeyPatch) -> None:
    patch_connection(monkeypatch, FakeConnection(error=OSError("connection reset")))
    with pytest.raises(guard.ReleaseGuardError) as caught:
        guard.https_get("api.github.com", "/x", {"Authorization": f"Bearer {TOKEN}"})
    assert "connection reset" in str(caught.value) and TOKEN not in str(caught.value)


def test_a_normal_answer_returns_status_and_body(monkeypatch: pytest.MonkeyPatch) -> None:
    connection = FakeConnection(status=200, body=b'{"ok": true}')
    patch_connection(monkeypatch, connection)
    assert guard.https_get("pypi.org", "/p", {"Accept": "x"}) == (200, b'{"ok": true}')
    assert connection.requested == [("GET", "/p", {"Accept": "x"})] and connection.closed


# --- selecting what to upload ----------------------------------------------------------------------------


def make_dist(tmp_path: Path) -> tuple[Path, dict[str, str]]:
    dist = tmp_path / "dist"
    dist.mkdir()
    contents = {WHEEL: b"wheel bytes", SDIST: b"sdist bytes"}
    for name, data in contents.items():
        (dist / name).write_bytes(data)
    return dist, {name: hashlib.sha256(data).hexdigest() for name, data in contents.items()}


def test_only_the_missing_files_are_copied(tmp_path: Path) -> None:
    dist, wanted = make_dist(tmp_path)
    assert guard.select_upload(dist, wanted, [SDIST], tmp_path / "upload") == 1
    assert sorted(p.name for p in (tmp_path / "upload").iterdir()) == [SDIST]


def test_a_file_that_changed_since_it_was_hashed_is_not_uploaded(tmp_path: Path) -> None:
    dist, wanted = make_dist(tmp_path)
    (dist / SDIST).write_bytes(b"tampered")
    with pytest.raises(guard.ReleaseGuardError, match="changed since it was hashed"):
        guard.select_upload(dist, wanted, [SDIST], tmp_path / "upload")


def test_a_name_that_is_not_part_of_the_build_is_refused(tmp_path: Path) -> None:
    dist, wanted = make_dist(tmp_path)
    with pytest.raises(guard.ReleaseGuardError, match="not a file of this build"):
        guard.select_upload(dist, wanted, ["other.whl"], tmp_path / "upload")


def test_the_upload_directory_must_be_new(tmp_path: Path) -> None:
    dist, wanted = make_dist(tmp_path)
    (tmp_path / "upload").mkdir()
    with pytest.raises(FileExistsError):
        guard.select_upload(dist, wanted, [WHEEL], tmp_path / "upload")


# --- the command line ------------------------------------------------------------------------------------


def run_cli(
    argv: list[str], remote: FakeRemote, capsys: pytest.CaptureFixture[str], sleeps: list[float] | None = None
) -> tuple[int, str, str]:
    sleeps = sleeps if sleeps is not None else []
    code = guard.main(argv, fetch=remote, sleep=sleeps.append)
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def pypi_argv(command: str, hashes: Path) -> list[str]:
    return [command, "--project", "unifiwifioptimizer", "--version", "0.5.0", "--hashes", str(hashes)]


def test_pypi_state_prints_output_lines_for_the_workflow(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    argv = pypi_argv("pypi-state", hashes_file(tmp_path))
    code, out, _ = run_cli(argv, FakeRemote(pypi({WHEEL: A})), capsys)
    assert code == 0 and out.splitlines() == ["state=partial", f"missing={SDIST}"]


def test_pypi_state_refuses_a_remote_that_differs(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    argv = pypi_argv("pypi-state", hashes_file(tmp_path))
    code, out, err = run_cli(argv, FakeRemote(pypi({WHEEL: C})), capsys)
    assert code == 1 and out == "" and "different bytes" in err


def verify_argv(tmp_path: Path) -> list[str]:
    return [
        *["pypi-verify", "--project", "unifiwifioptimizer", "--version", "0.5.0"],
        *["--hashes", str(hashes_file(tmp_path)), "--attempts", "3", "--delay", "7"],
    ]


def test_verify_retries_while_the_index_catches_up_and_then_succeeds(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    remote = FakeRemote(pypi({WHEEL: A}))
    sleeps: list[float] = []

    def settle(host: str, path: str, headers: Mapping[str, str]) -> tuple[int, bytes]:
        if len(sleeps) == 2:
            remote.answers = [pypi(WANTED)]
        return remote(host, path, headers)

    code = guard.main(verify_argv(tmp_path), fetch=settle, sleep=sleeps.append)
    assert code == 0 and sleeps == [7.0, 7.0]
    assert capsys.readouterr().out == ""


def test_verify_gives_up_after_the_last_attempt_and_names_what_is_missing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    sleeps: list[float] = []
    code, _, err = run_cli(verify_argv(tmp_path), FakeRemote(pypi({WHEEL: A})), capsys, sleeps)
    assert code == 1 and sleeps == [7.0, 7.0] and f"PyPI lacks: {SDIST}" in err


def test_verify_does_not_retry_a_remote_that_differs(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    sleeps: list[float] = []
    code, _, err = run_cli(verify_argv(tmp_path), FakeRemote(pypi({WHEEL: C})), capsys, sleeps)
    assert code == 1 and sleeps == [] and "different bytes" in err


def release_argv(tmp_path: Path) -> list[str]:
    return ["release-state", "--repository", "o/r", "--tag", "v0.5.0", "--hashes", str(hashes_file(tmp_path))]


def test_release_state_needs_the_token_and_never_echoes_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("GH_TOKEN", raising=False)
    code, _, err = run_cli(release_argv(tmp_path), FakeRemote(), capsys)
    assert code == 1 and "GH_TOKEN is not set" in err
    monkeypatch.setenv("GH_TOKEN", TOKEN)
    code, out, err = run_cli(release_argv(tmp_path), FakeRemote(("api.github.com", "/repos", 500, {})), capsys)
    assert code == 1 and TOKEN not in out + err


def test_release_state_distinguishes_no_release_a_draft_and_a_published_release(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("GH_TOKEN", TOKEN)
    none = FakeRemote(("api.github.com", "/repos/o/r/releases", 200, []))
    _, out, _ = run_cli(release_argv(tmp_path), none, capsys)
    assert out.splitlines()[0] == "release=absent"
    draft = FakeRemote(*release_pages(release("v0.5.0", {}, draft=True)))
    _, out, _ = run_cli(release_argv(tmp_path), draft, capsys)
    assert out.splitlines()[:2] == ["release=draft", "state=absent"]
    partial = FakeRemote(*release_pages(release("v0.5.0", {WHEEL: A})))
    _, out, _ = run_cli(release_argv(tmp_path), partial, capsys)
    assert out.splitlines() == ["release=published", "state=partial", f"missing={SDIST}"]
    complete = FakeRemote(*release_pages(release("v0.5.0", WANTED)))
    _, out, _ = run_cli(release_argv(tmp_path), complete, capsys)
    assert out.splitlines() == ["release=published", "state=complete", "missing="]


def select_argv(tmp_path: Path, dist: Path, wanted: Mapping[str, str]) -> list[str]:
    return [
        *["select-upload", "--dist", str(dist), "--hashes", str(hashes_file(tmp_path, wanted))],
        *["--project", "unifiwifioptimizer", "--version", "0.5.0", "--out", str(tmp_path / "upload")],
    ]


def uploaded(tmp_path: Path) -> list[str]:
    return sorted(p.name for p in (tmp_path / "upload").iterdir())


def test_select_upload_asks_pypi_right_now_and_copies_everything_when_nothing_is_there(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    dist, wanted = make_dist(tmp_path)
    code, out, _ = run_cli(select_argv(tmp_path, dist, wanted), FakeRemote(("pypi.org", "/pypi/", 404, {})), capsys)
    assert code == 0 and out == "count=2\n" and uploaded(tmp_path) == sorted(wanted)


def test_select_upload_copies_only_what_pypi_lacks_after_an_interrupted_upload(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    dist, wanted = make_dist(tmp_path)
    remote = FakeRemote(pypi({WHEEL: wanted[WHEEL]}))
    code, out, _ = run_cli(select_argv(tmp_path, dist, wanted), remote, capsys)
    assert code == 0 and out == "count=1\n" and uploaded(tmp_path) == [SDIST]


def test_select_upload_copies_nothing_when_pypi_already_holds_the_build(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    dist, wanted = make_dist(tmp_path)
    code, out, _ = run_cli(select_argv(tmp_path, dist, wanted), FakeRemote(pypi(wanted)), capsys)
    assert code == 0 and out == "count=0\n" and uploaded(tmp_path) == []


def test_select_upload_refuses_a_pypi_that_holds_other_bytes_and_creates_no_upload_directory(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    dist, wanted = make_dist(tmp_path)
    code, _, err = run_cli(select_argv(tmp_path, dist, wanted), FakeRemote(pypi({WHEEL: C})), capsys)
    assert code == 1 and "different bytes" in err and not (tmp_path / "upload").exists()


def verify_dir_argv(tmp_path: Path, directory: Path, wanted: Mapping[str, str]) -> list[str]:
    return ["verify-dir", "--dir", str(directory), "--hashes", str(hashes_file(tmp_path, wanted))]


def test_verify_dir_accepts_exactly_the_hashed_files(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    dist, wanted = make_dist(tmp_path)
    assert run_cli(verify_dir_argv(tmp_path, dist, wanted), FakeRemote(), capsys)[0] == 0


@pytest.mark.parametrize(
    "change", ["extra-file", "hidden-file", "subdirectory", "missing-file", "other-bytes", "symlink"]
)
def test_verify_dir_refuses_anything_but_the_hashed_files(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], change: str
) -> None:
    dist, wanted = make_dist(tmp_path)
    if change == "extra-file":
        (dist / "extra.whl").write_bytes(b"x")
    elif change == "hidden-file":
        (dist / ".hidden").write_bytes(b"x")
    elif change == "subdirectory":
        (dist / "nested").mkdir()
    elif change == "missing-file":
        (dist / SDIST).unlink()
    elif change == "other-bytes":
        (dist / SDIST).write_bytes(b"other")
    else:
        # The link points at a file with exactly the hashed bytes: only the link itself gives it away.
        genuine = tmp_path / "genuine"
        (dist / SDIST).rename(genuine)
        (dist / SDIST).symlink_to(genuine)
    code, _, err = run_cli(verify_dir_argv(tmp_path, dist, wanted), FakeRemote(), capsys)
    assert code == 1 and err.startswith("release_guard: ")
