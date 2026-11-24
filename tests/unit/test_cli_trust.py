"""`trust-host-keys` through `main`: arguments, confirmation wiring, exit codes, no raw strings on the terminal."""

import io
import subprocess
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import cast

import pytest

from tests.unit.app.test_trust_decision import Memory, Scans, cand, subject
from tests.unit.printed import PLAIN, given
from tests.unit.test_cli_commands import SCANNING_SITE, FixtureApi, configured, loaded
from unifiwifioptimizer.adapters.ssh.hostkeys import HostKeyCandidate, KnownHostsWriter, TrustBasis
from unifiwifioptimizer.app.run import RunResult
from unifiwifioptimizer.app.trust import TrustOutcome, TrustPolicy, TrustReport, TrustResult, check_host_keys
from unifiwifioptimizer.cli import main as cli
from unifiwifioptimizer.cli.exit_codes import ExitCode
from unifiwifioptimizer.cli.prompt import terminal_confirm
from unifiwifioptimizer.domain.errors import HostKeyTrustError
from unifiwifioptimizer.domain.hostkeys import TrustRefusalKind


@pytest.fixture
def wired(monkeypatch: pytest.MonkeyPatch) -> Iterator[dict[str, object]]:
    seen: dict[str, object] = {}
    monkeypatch.setattr(cli, "load_config", lambda explicit=None, commands=None: loaded())
    monkeypatch.setattr(cli, "_client", lambda loaded_config, args, commands: (FixtureApi(), None))

    def fake_trust(
        api: object, cfg: object, store: object, selector: str, only: list[str], **kwargs: object
    ) -> TrustReport:
        report = kwargs.pop("report")
        seen.update(selector=selector, only=only, store=store, **kwargs)
        results = (
            TrustResult(ap_name="AP-1", outcome=TrustOutcome.STORED, basis=TrustBasis.CONTROLLER, detail="SHA256:abc"),
            TrustResult(
                ap_name="AP\x1b[2J", outcome=TrustOutcome.FAILED, basis=None, detail="2 host keys offered",
                next_step="report it with the access point's firmware version",
            ),
        )  # fmt: skip
        for result in results:
            report(result)  # type: ignore[operator]
        return TrustReport(site_id="default", results=results)

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
    captured = capsys.readouterr()
    out = captured.out
    assert "AP-1: stored (controller fingerprint) SHA256:abc" in out
    assert "\x1b" not in out and "failed 2 host keys offered; report it with the access point's firmware version" in out
    assert captured.err == (
        "unifiwifioptimizer: exit 5: site default: 1 access point failed; the result lines name each reason and "
        "its next step\n"
    )


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
    def failing(explicit: Path | None = None, commands: object = None) -> None:
        raise HostKeyTrustError(
            TrustRefusalKind.SOURCES_DISAGREE,
            "the configured host-key pin and the fingerprint the controller reports differ",
        )

    monkeypatch.setattr(cli, "load_config", failing)
    assert cli.main(["trust-host-keys", "--site", "default"]) == ExitCode.HOST_KEY
    assert "pin and the fingerprint" in capsys.readouterr().err


def test_exit_code_mapping_covers_the_host_key_class() -> None:
    assert cli._exit_code_for(HostKeyTrustError(TrustRefusalKind.STORE_CHANGED, "x")) is ExitCode.HOST_KEY


@pytest.mark.security("T19")
def test_trust_host_keys_exits_7_when_ssh_keyscan_is_missing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # Through the real trust flow and the real keyscan runner: only the spawn is replaced, so the mapping of a
    # missing binary onto the environment exit code is what this test exercises.
    monkeypatch.setattr(cli, "load_config", lambda explicit=None, commands=None: configured({"default": SCANNING_SITE}))
    monkeypatch.setattr(cli, "_client", lambda loaded_config, args, commands: (FixtureApi(), None))

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

    monkeypatch.setattr(cli, "load_config", lambda explicit=None, commands=None: configured({"default": SCANNING_SITE}))
    monkeypatch.setattr(cli, "_client", lambda loaded_config, args, commands: (FixtureApi(), None))
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
        [subject()], store,
        TrustPolicy(assume_yes=False, accept_unverified=False, confirm=terminal_confirm, commands=PLAIN),
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


def test_the_closing_line_counts_failures_only_and_pluralises(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def result(name: str, outcome: TrustOutcome) -> TrustResult:
        return TrustResult(ap_name=name, outcome=outcome, basis=None, detail="")

    results = (
        result("A", TrustOutcome.FAILED),
        result("B", TrustOutcome.DECLINED),
        result("C", TrustOutcome.NOT_ON_CONTROLLER),
        result("D", TrustOutcome.FAILED),
    )

    def fake_trust(*args: object, **kwargs: object) -> TrustReport:
        return TrustReport(site_id="default", results=results)

    monkeypatch.setattr(cli, "load_config", lambda explicit=None, commands=None: loaded())
    monkeypatch.setattr(cli, "_client", lambda loaded_config, args, commands: (FixtureApi(), None))
    monkeypatch.setattr(cli, "trust_host_keys", fake_trust)
    assert cli.main(["trust-host-keys", "--site", "default", "--known-hosts", "/state/kh"]) == ExitCode.HOST_KEY
    assert capsys.readouterr().err == (
        "unifiwifioptimizer: exit 5: site default: 2 access points failed; the result lines name each reason and "
        "its next step\n"
    )
    results = (result("A", TrustOutcome.STORED), result("B", TrustOutcome.DECLINED))  # type: ignore[assignment]
    assert cli.main(["trust-host-keys", "--site", "default", "--known-hosts", "/state/kh"]) == ExitCode.OK
    assert capsys.readouterr().err == ""


# --- the record is streamed: what was stored before an interruption is on stdout ----------------------------------


@pytest.fixture
def real_trust(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[tuple[list[str], str]]:
    """The real `trust_host_keys` over the fixture access points, a real store file and a keyscan by address; yields
    the access point names in the order the command handles them and the one that has no verification basis."""
    from tests.unit.app.test_trust import (
        FixtureApi as TrustApi,
    )
    from tests.unit.app.test_trust import (
        access_points,
        controller_fingerprints,
        key_for,
        names_by_ip,
    )
    from tests.unit.app.test_trust import (
        loaded as trust_loaded,
    )
    from unifiwifioptimizer.app import trust as trust_module
    from unifiwifioptimizer.domain.hostkeys import normalize_fingerprint

    forms = controller_fingerprints()
    unverified = next(n for n, text in forms.items() if not text)
    ordered = [n for n, text in forms.items() if text] + [unverified]
    handled = [ordered[0], *sorted(ordered[1:])]
    offered: dict[str, list[HostKeyCandidate]] = {}
    for ap in access_points():
        fingerprint = normalize_fingerprint(ap.ssh_host_key_fingerprint) if ap.ssh_host_key_fingerprint else None
        offered[ap.name] = (
            [key_for(1)]
            if fingerprint is None
            else [HostKeyCandidate("ssh-ed25519", key_for(2).key_base64, fingerprint, fingerprint)]
        )
    config = trust_loaded({"ssh": {}, "neighbors": {ordered[0]: ordered[1:]}})
    monkeypatch.setattr(cli, "load_config", lambda explicit=None, commands=None: config)
    monkeypatch.setattr(cli, "_client", lambda loaded_config, args, commands: (TrustApi(), None))
    monkeypatch.setattr(trust_module, "keyscan", lambda address, port, key_type=None: offered[names_by_ip[address]])
    yield handled, unverified


def test_an_interruption_at_a_later_question_leaves_the_stored_keys_on_stdout(
    real_trust: tuple[list[str], str],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    handled, unverified = real_trust
    before = handled[: handled.index(unverified)]
    assert before, "the interruption must come after a stored key"
    asked: list[str] = []

    def interrupted(prompt: object) -> bool:
        asked.append("question")
        raise KeyboardInterrupt

    monkeypatch.setattr(cli, "terminal_confirm", interrupted)
    argv = ["trust-host-keys", "--site", "default", "--yes", "--known-hosts", str(tmp_path / "kh")]
    assert cli.main(argv) == ExitCode.INTERRUPTED
    captured = capsys.readouterr()
    stored = [line for line in captured.out.splitlines() if ": stored (controller fingerprint)" in line]
    assert [line.split(":")[0] for line in stored] == before and asked == ["question"]
    assert "interrupted" in captured.err and "exit 5" not in captured.err


def test_a_store_error_at_a_later_access_point_leaves_the_stored_keys_on_stdout(
    real_trust: tuple[list[str], str],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    from unifiwifioptimizer.domain.errors import ConfigError

    handled, _ = real_trust

    class Breaking(KnownHostsWriter):
        added = 0

        def add(self, entry: object) -> None:
            type(self).added += 1
            if type(self).added == 2:
                raise ConfigError("known_hosts", "cannot write")
            super().add(entry)  # type: ignore[arg-type]

    monkeypatch.setattr(cli, "KnownHostsWriter", Breaking)
    argv = ["trust-host-keys", "--site", "default", "--yes", "--known-hosts", str(tmp_path / "kh")]
    assert cli.main(argv) == ExitCode.CONFIG
    captured = capsys.readouterr()
    assert captured.out.splitlines()[0].startswith(f"{handled[0]}: stored (controller fingerprint)")
    assert "cannot write" in captured.err


def test_the_run_gate_prints_the_step_of_a_refusal_on_stderr_through_the_real_check(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    import argparse
    import dataclasses

    from tests.unit.app.test_trust_refusals import EXPECTED_STEPS
    from unifiwifioptimizer.app import trust as trust_module

    monkeypatch.setattr(trust_module, "keyscan", lambda address, port, key_type=None: [cand(1)])
    gate = cli._host_key_gate(argparse.Namespace(config_file=None, known_hosts=tmp_path / "kh"), {}, PLAIN)
    gate([dataclasses.replace(subject(), controller_fingerprint=cand(2).sha256.text)])
    assert capsys.readouterr().err.splitlines() == [
        "unifiwifioptimizer: checking host keys...",
        "unifiwifioptimizer: AP-1: failed (controller fingerprint) none of the 1 offered host keys matches the "
        f"controller fingerprint; {EXPECTED_STEPS[TrustRefusalKind.KEY_MISMATCH_CONTROLLER]}",
    ]


def test_the_closing_line_passes_the_site_id_through_safe_text(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    failed = TrustResult(ap_name="A", outcome=TrustOutcome.FAILED, basis=None, detail="x")
    monkeypatch.setattr(cli, "load_config", lambda explicit=None, commands=None: loaded())
    monkeypatch.setattr(cli, "_client", lambda loaded_config, args, commands: (FixtureApi(), None))
    monkeypatch.setattr(
        cli, "trust_host_keys", lambda *args, **kwargs: TrustReport(site_id="x\x1b[2J", results=(failed,))
    )
    assert cli.main(["trust-host-keys", "--site", "default", "--known-hosts", "/state/kh"]) == ExitCode.HOST_KEY
    assert "\x1b" not in capsys.readouterr().err


def test_the_trust_command_and_the_gate_repeat_the_store_in_the_step_they_print(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    import argparse

    from tests.unit.app.test_trust import FixtureApi as TrustApi
    from tests.unit.app.test_trust import access_points, key_for
    from tests.unit.app.test_trust import loaded as trust_loaded
    from unifiwifioptimizer.adapters.ssh.hostkeys import KnownHostEntry
    from unifiwifioptimizer.app import trust as trust_module
    from unifiwifioptimizer.domain.hostkeys import host_key_alias

    ap = next(ap for ap in access_points() if not ap.ssh_host_key_fingerprint)
    store_path = tmp_path / "known hosts"
    alias = host_key_alias("https://unifi.example:443", "default", ap.mac)
    store_path.write_text(
        "".join(f"{KnownHostEntry(alias, 'ssh-ed25519', key_for(seed).key_base64).line}\n" for seed in (1, 2))
    )
    store_path.chmod(0o600)
    monkeypatch.setattr(
        cli, "load_config", lambda explicit=None, commands=None: trust_loaded({"ssh": {}, "neighbors": {ap.name: []}})
    )
    monkeypatch.setattr(cli, "_client", lambda loaded_config, args, commands: (TrustApi(), None))
    monkeypatch.setattr(trust_module, "keyscan", lambda address, port, key_type=None: [key_for(3)])
    expected = (
        "`unifiwifioptimizer --config-file=/etc/uwo/home.yaml trust-host-keys --site default "
        f"--known-hosts='{store_path}'`"
    )
    argv = ["--config-file", "/etc/uwo/home.yaml", "trust-host-keys", "--site", "default", "--known-hosts"]

    assert cli.main([*argv, str(store_path)]) == ExitCode.HOST_KEY
    assert expected in capsys.readouterr().out

    gate = cli._host_key_gate(
        argparse.Namespace(config_file=Path("/etc/uwo/home.yaml"), known_hosts=store_path),
        {},
        given(config_file="/etc/uwo/home.yaml", known_hosts=str(store_path)),
    )
    import dataclasses

    from tests.unit.app.test_trust_decision import subject

    gate([dataclasses.replace(subject(), name=ap.name, alias=alias, mac=ap.mac, address=ap.ip)])
    assert expected in capsys.readouterr().err


@pytest.mark.parametrize("store", [".", "..", "/", "sub/..", "directory"])
@pytest.mark.parametrize(
    "argv",
    [["trust-host-keys", "--site", "default"], ["run"], ["run", "--no-scan"], ["run", "--json"]],
    ids=["trust", "run", "run-no-scan", "run-json"],
)
def test_a_store_path_that_is_no_file_stops_the_command_before_anything_is_done(
    argv: list[str],
    store: str,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    def never(*args: object, **kwargs: object) -> None:
        raise AssertionError("work started with a store path that is no file")

    monkeypatch.chdir(tmp_path)
    (tmp_path / "directory").mkdir()
    monkeypatch.setattr(cli, "load_config", lambda explicit=None, commands=None: loaded())
    monkeypatch.setattr(cli, "_client", lambda loaded_config, args, commands: (FixtureApi(), None))
    monkeypatch.setattr(cli, "trust_host_keys", never)
    monkeypatch.setattr(cli, "run_analysis", never)
    monkeypatch.setattr(cli, "load_profiles", lambda override, location: type("P", (), {"profiles": None})())
    assert cli.main([*argv, "--known-hosts", store]) == ExitCode.CONFIG
    err = capsys.readouterr().err
    assert (f"{Path(store)} names no file" if store != "directory" else "directory is not a regular file") in err
    assert [p.name for p in tmp_path.iterdir()] == ["directory"]
