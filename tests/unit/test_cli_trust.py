"""`trust-host-keys` through `main`: arguments, confirmation wiring, exit codes, no raw strings on the terminal."""

import subprocess
from collections.abc import Iterator
from pathlib import Path

import pytest

from tests.unit.test_cli_commands import SCANNING_SITE, FixtureApi, configured, loaded
from unifiwifioptimizer.adapters.ssh.hostkeys import TrustBasis
from unifiwifioptimizer.app.trust import TrustOutcome, TrustReport, TrustResult
from unifiwifioptimizer.cli import main as cli
from unifiwifioptimizer.cli.exit_codes import ExitCode
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
def test_trust_host_keys_defaults_to_the_xdg_store_and_asks_through_the_terminal(
    wired: dict[str, object], monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("XDG_STATE_HOME", "/xdg-state")
    assert cli.main(["trust-host-keys", "--site", "default", "--accept-unverified"]) == ExitCode.HOST_KEY
    assert str(getattr(wired["store"], "path", "")) == "/xdg-state/unifiwifioptimizer/known_hosts"
    assert wired["accept_unverified"] is True and wired["assume_yes"] is False
    confirm = wired["confirm"]
    assert callable(confirm)
    # Without a terminal the question is printed and declined — never answered by default.
    monkeypatch.setattr("sys.stdin", type("NoTty", (), {"isatty": staticmethod(lambda: False)})())
    assert confirm("AP-1: store key\x1b[31m?") is False
    err = capsys.readouterr().err
    assert "no terminal to ask; declined" in err and "\x1b" not in err
    monkeypatch.setattr("sys.stdin", type("Tty", (), {"isatty": staticmethod(lambda: True)})())
    monkeypatch.setattr("builtins.input", lambda prompt: "y")
    assert confirm("AP-1: store key?") is True
    monkeypatch.setattr("builtins.input", lambda prompt: "")
    assert confirm("AP-1: store key?") is False


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
