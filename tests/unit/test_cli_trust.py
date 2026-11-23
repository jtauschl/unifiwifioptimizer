"""`trust-host-keys` through `main`: arguments, confirmation wiring, exit codes, no raw strings on the terminal."""

import io
import subprocess
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import cast

import pytest

from tests.unit.app.test_trust_decision import Memory, Scans, cand, subject
from tests.unit.test_cli_commands import SCANNING_SITE, FixtureApi, configured, loaded
from unifiwifioptimizer.adapters.ssh.hostkeys import KnownHostsWriter, TrustBasis
from unifiwifioptimizer.app.run import RunResult
from unifiwifioptimizer.app.trust import TrustOutcome, TrustPolicy, TrustReport, TrustResult, check_host_keys
from unifiwifioptimizer.cli import main as cli
from unifiwifioptimizer.cli.exit_codes import ExitCode
from unifiwifioptimizer.cli.prompt import terminal_confirm
from unifiwifioptimizer.domain.errors import HostKeyTrustError


@pytest.fixture
def wired(monkeypatch: pytest.MonkeyPatch) -> Iterator[dict[str, object]]:
    seen: dict[str, object] = {}
    monkeypatch.setattr(cli, "load_config", lambda explicit=None: loaded())
    monkeypatch.setattr(cli, "_client", lambda loaded_config, args: (FixtureApi(), None))

    def fake_trust(
        api: object, cfg: object, store: object, selector: str, only: list[str], **kwargs: object
    ) -> TrustReport:
        seen.update(selector=selector, only=only, store=store, **kwargs)
        return TrustReport(
            site_id="default",
            results=(
                TrustResult(
                    ap_name="AP-1", outcome=TrustOutcome.STORED, basis=TrustBasis.CONTROLLER, detail="SHA256:abc"
                ),
                TrustResult(ap_name="AP\x1b[2J", outcome=TrustOutcome.FAILED, basis=None, detail="2 host keys offered"),
            ),
        )

    monkeypatch.setattr(cli, "trust_host_keys", fake_trust)
    yield seen


@pytest.mark.security("T8", "T12")
def test_trust_host_keys_wires_arguments_prints_each_result_and_exits_5_on_a_failure(
    wired: dict[str, object], capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    store_path = Path("/state/kh")
    code = cli.main(
        [
            "trust-host-keys",
            "--site",
            "default",
            "--ap",
            "AP-1",
            "--ap",
            "AP-2",
            "--yes",
            "--known-hosts",
            str(store_path),
        ]
    )
    assert code == ExitCode.HOST_KEY
    assert wired["selector"] == "default" and wired["only"] == ["AP-1", "AP-2"]
    assert wired["assume_yes"] is True and wired["accept_unverified"] is False
    assert getattr(wired["store"], "path", None) == store_path
    out = capsys.readouterr().out
    assert "AP-1: stored (controller fingerprint) SHA256:abc" in out
    assert "\x1b" not in out and "failed 2 host keys offered" in out


@pytest.mark.security("T8")
def test_trust_host_keys_defaults_to_the_xdg_store_and_asks_through_the_terminal_prompt(
    wired: dict[str, object], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("XDG_STATE_HOME", "/xdg-state")
    assert cli.main(["trust-host-keys", "--site", "default", "--accept-unverified"]) == ExitCode.HOST_KEY
    assert str(getattr(wired["store"], "path", "")) == "/xdg-state/unifiwifioptimizer/known_hosts"
    assert wired["accept_unverified"] is True and wired["assume_yes"] is False
    assert wired["confirm"] is terminal_confirm
    assert type(wired["store"]) is KnownHostsWriter


def test_trust_host_keys_requires_the_site_option() -> None:
    with pytest.raises(SystemExit) as exc:
        cli.main(["trust-host-keys"])
    assert exc.value.code == ExitCode.USAGE


def test_a_trust_error_exits_5(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    def failing(explicit: Path | None = None) -> None:
        raise HostKeyTrustError("the configured host-key pin and the fingerprint the controller reports differ")

    monkeypatch.setattr(cli, "load_config", failing)
    assert cli.main(["trust-host-keys", "--site", "default"]) == ExitCode.HOST_KEY
    assert "pin and the fingerprint" in capsys.readouterr().err


def test_exit_code_mapping_covers_the_host_key_class() -> None:
    assert cli._exit_code_for(HostKeyTrustError("x")) is ExitCode.HOST_KEY


@pytest.mark.security("T19")
def test_trust_host_keys_exits_7_when_ssh_keyscan_is_missing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # Through the real trust flow and the real keyscan runner: only the spawn is replaced, so the mapping of a
    # missing binary onto the environment exit code is what this test exercises.
    monkeypatch.setattr(cli, "load_config", lambda explicit=None: configured({"default": SCANNING_SITE}))
    monkeypatch.setattr(cli, "_client", lambda loaded_config, args: (FixtureApi(), None))

    def missing(argv: list[str], **kwargs: object) -> None:
        raise FileNotFoundError(argv[0])

    monkeypatch.setattr(subprocess, "run", missing)
    assert (
        cli.main(["trust-host-keys", "--site", "default", "--known-hosts", str(tmp_path / "known_hosts"), "--yes"])
        == ExitCode.ENVIRONMENT
    )
    assert "ssh-keyscan not found" in capsys.readouterr().err


# --- the host-key gate of `run` ---------------------------------------------------------------------------------


class Stream:
    def __init__(self, tty: bool) -> None:
        self._tty = tty
        self.written: list[str] = []

    def isatty(self) -> bool:
        return self._tty

    def write(self, text: str) -> int:
        self.written.append(text)
        return len(text)

    def flush(self) -> None:
        return None


@pytest.fixture
def gate_wiring(monkeypatch: pytest.MonkeyPatch) -> dict[str, object]:
    seen: dict[str, object] = {}

    def record(*args: object, **kwargs: object) -> RunResult:
        seen["gate"] = kwargs.get("host_key_gate")
        return RunResult(reports=(), outcomes=(), host_key_gate_ran=False)

    monkeypatch.setattr(cli, "load_config", lambda explicit=None: configured({"default": SCANNING_SITE}))
    monkeypatch.setattr(cli, "_client", lambda loaded_config, args: (FixtureApi(), None))
    monkeypatch.setattr(cli, "run_analysis", record)
    return seen


def streams(monkeypatch: pytest.MonkeyPatch, *, stdin: bool, stdout: bool, stderr: bool) -> None:
    monkeypatch.setattr("sys.stdin", Stream(stdin))
    monkeypatch.setattr("sys.stdout", Stream(stdout))
    monkeypatch.setattr("sys.stderr", Stream(stderr))


@pytest.mark.security("T8")
def test_run_asks_about_host_keys_only_with_a_terminal_on_stdin_stdout_and_stderr(
    gate_wiring: dict[str, object], monkeypatch: pytest.MonkeyPatch
) -> None:
    streams(monkeypatch, stdin=True, stdout=True, stderr=True)
    assert cli.main(["run"]) == ExitCode.OK
    assert callable(gate_wiring["gate"])
    for missing in ("stdin", "stdout", "stderr"):
        flags = {"stdin": True, "stdout": True, "stderr": True, missing: False}
        streams(monkeypatch, **flags)
        assert cli.main(["run"]) == ExitCode.OK
        assert gate_wiring["gate"] is None, f"{missing} is not a terminal"


@pytest.mark.security("T8")
def test_run_never_asks_with_no_scan_and_the_gate_stores_nothing_on_its_own(
    gate_wiring: dict[str, object], monkeypatch: pytest.MonkeyPatch
) -> None:
    streams(monkeypatch, stdin=True, stdout=True, stderr=True)
    assert cli.main(["run", "--no-scan"]) == ExitCode.OK
    assert gate_wiring["gate"] is None
    seen: dict[str, object] = {}

    def fake_check(
        subjects: object, writer: object, policy: object, report: object, *args: object, **kwargs: object
    ) -> None:
        seen.update(subjects=subjects, writer=writer, policy=policy)

    monkeypatch.setattr(cli, "check_host_keys", fake_check)
    assert cli.main(["run", "--known-hosts", "/state/kh"]) == ExitCode.OK
    gate = cast("Callable[[list[str]], None]", gate_wiring["gate"])
    gate(["subject"])
    policy = seen["policy"]
    assert getattr(policy, "assume_yes", None) is False and getattr(policy, "accept_unverified", None) is False
    assert getattr(policy, "confirm", None) is terminal_confirm
    assert type(seen["writer"]) is KnownHostsWriter and getattr(seen["writer"], "path", None) == Path("/state/kh")


@pytest.mark.security("T8")
def test_the_chain_from_the_decision_to_the_terminal_declines_with_the_warning_and_the_way_to_answer(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr("sys.stdin", io.StringIO(""))
    store = Memory()
    results: list[TrustResult] = []
    check_host_keys(
        [subject()], store, TrustPolicy(assume_yes=False, accept_unverified=False, confirm=terminal_confirm),
        results.append, Scans([], [cand(1)]),
    )  # fmt: skip
    assert [str(r.outcome) for r in results] == ["declined"] and store.rows == []
    assert capsys.readouterr().err.splitlines() == [
        f"unifiwifioptimizer: default: AP-1: store host key {cand(1).sha256.text} on first use? "
        "— no terminal to ask; declined",
        "unifiwifioptimizer: access point AP-1, MAC 02:00:00:00:00:01, address 192.168.1.2",
        "unifiwifioptimizer: neither a pin nor the controller verifies this key",
        "unifiwifioptimizer: if you accept it, the scan results come from whoever holds this key",
        "unifiwifioptimizer: the scan also logs in to them with the password for the site's access points",
        "unifiwifioptimizer: to store it without asking, add to the command: --ap=AP-1 --accept-unverified",
    ]
