"""The scanner against the harness access point: dropbear and OpenSSH servers, the real remote script, the
stubbed radios, and every failure path the plan names."""

import subprocess
import time
from pathlib import Path

import pytest

from tests.integration.harness.conftest import SCAN_PASSWORD, SCAN_USER, Harness
from unifiwifioptimizer.adapters.ssh.hostkeys import KnownHostsStore, keyscan
from unifiwifioptimizer.adapters.ssh.iw_parser import parse_scan_output
from unifiwifioptimizer.adapters.ssh.openssh import CALL_TIMEOUT_S, OpenSshScanner, build_invocation, load_script
from unifiwifioptimizer.domain.errors import (
    HostKeyMismatchError,
    HostKeyUnknownError,
    ScanOutputTooLargeError,
    ScanTimeoutError,
    SshAuthenticationError,
)
from unifiwifioptimizer.domain.hostkeys import host_key_alias
from unifiwifioptimizer.domain.models import Band
from unifiwifioptimizer.domain.scan import BandScanStatus, ScanTarget, SshAuthMethod, SshCredentials
from unifiwifioptimizer.domain.secrets import Secret

pytestmark = pytest.mark.integration
ASKPASS = Path(__file__).resolve().parents[3] / ".venv" / "bin" / "unifiwifioptimizer-askpass"
ORIGIN = "https://unifi.example:443"
MAC = "02:00:00:00:00:04"


def target(
    harness: Harness, port: int, *, toggle: bool = False, attempts: int = 1, password: str = SCAN_PASSWORD
) -> ScanTarget:
    return ScanTarget(
        site_id="default",
        ap_mac=MAC,
        ap_name="AP-harness",
        address=harness.address,
        port=port,
        host_key_alias=host_key_alias(ORIGIN, "default", MAC),
        credentials=SshCredentials(
            user=SCAN_USER, method=SshAuthMethod.PASSWORD, password=Secret(password), key_file=None
        ),
        scan_attempts=attempts,
        interface_toggle=toggle,
        allow_public_address=False,
    )


def trusted_store(tmp_path: Path, harness: Harness, port: int) -> KnownHostsStore:
    store = KnownHostsStore(tmp_path / "state" / "known_hosts")
    candidates = keyscan(harness.address, port)
    assert candidates, "the harness server offered no host key"
    store.add(candidates[0].entry(host_key_alias(ORIGIN, "default", MAC)))
    return store


def scanner(store: KnownHostsStore, *, timeout: float = CALL_TIMEOUT_S) -> OpenSshScanner:
    assert ASKPASS.is_file(), "the askpass console script must be installed in the project venv"
    # The harness publishes the access point on loopback, which the production gate refuses by design.
    return OpenSshScanner(store, lambda address: True, askpass=ASKPASS, call_timeout_s=timeout)


def test_askpass_helper_is_installed_as_a_console_script() -> None:
    result = subprocess.run(
        [str(ASKPASS)], capture_output=True, text=True, env={"UWO_SSH_PASSWORD": "x", "PATH": "/usr/bin:/bin"}
    )
    assert result.returncode == 0 and result.stdout == "x\n"


@pytest.mark.parametrize("server", ["dropbear", "sshd"])
def test_a_full_scan_over_each_server_kind(fresh_ap: Harness, tmp_path: Path, server: str) -> None:
    port = fresh_ap.dropbear_port if server == "dropbear" else fresh_ap.sshd_port
    result = scanner(trusted_store(tmp_path, fresh_ap, port)).scan(target(fresh_ap, port, attempts=2))
    two = result.band(Band.GHZ_2)
    five = result.band(Band.GHZ_5)
    assert two is not None and five is not None
    assert two.status is BandScanStatus.OK and two.interface == "apcli0"
    assert [(r.bssid, r.rssi_dbm, r.frequency_mhz, r.ssid) for r in two.readings] == [
        ("02:00:00:00:00:a1", -58, 2437, "Harness-2G"),
        ("02:00:00:00:00:b2", -71, 2412, "Neighbour\twith\ttabs"),
        # `iw` printed the escape as `\x1b`; the parser rebuilds the byte, the report layer sanitises it.
        ("02:00:00:00:00:c3", -84, 2462, "\x1b[31mescape\x1b[0m"),
    ]
    # apclii0 is down and the configuration forbids toggling: reported, not touched.
    assert five.status is BandScanStatus.INTERFACE_DOWN and five.readings == ()
    assert result.meta.model_name == "U6-Lite-Harness" and result.meta.watchdog == "timeout"
    assert fresh_ap.toggles() == []


def test_the_interface_toggle_brings_the_scan_interface_up_and_restores_it(fresh_ap: Harness, tmp_path: Path) -> None:
    port = fresh_ap.dropbear_port
    result = scanner(trusted_store(tmp_path, fresh_ap, port)).scan(target(fresh_ap, port, toggle=True))
    five = result.band(Band.GHZ_5)
    assert five is not None and five.status is BandScanStatus.OK and five.interface == "apclii0"
    assert [r.bssid for r in five.readings] == ["02:00:00:00:00:d4", "02:00:00:00:00:e5"]
    assert fresh_ap.toggles() == ["apclii0 up", "apclii0 down"]
    assert fresh_ap.exec_ap("sh", "-c", "test -e /run/ifstate/apclii0.up", check=False).returncode == 1


def test_a_wrong_password_is_an_authentication_failure(fresh_ap: Harness, tmp_path: Path) -> None:
    port = fresh_ap.dropbear_port
    with pytest.raises(SshAuthenticationError, match="authentication failed"):
        scanner(trusted_store(tmp_path, fresh_ap, port)).scan(target(fresh_ap, port, password="wrong"))


def test_an_unknown_alias_never_connects_and_a_wrong_stored_key_is_refused_before_authentication(
    fresh_ap: Harness, tmp_path: Path
) -> None:
    port = fresh_ap.dropbear_port
    empty = KnownHostsStore(tmp_path / "empty" / "known_hosts")
    with pytest.raises(HostKeyUnknownError):
        scanner(empty).scan(target(fresh_ap, port))
    wrong = KnownHostsStore(tmp_path / "wrong" / "known_hosts")
    alias = host_key_alias(ORIGIN, "default", MAC)
    # The other server's key under this alias: a real key, the wrong one.
    wrong.add(keyscan(fresh_ap.address, fresh_ap.sshd_port)[0].entry(alias))
    with pytest.raises(HostKeyMismatchError, match="does not match the stored one"):
        scanner(wrong).scan(target(fresh_ap, port))


def test_a_hanging_scan_is_killed_at_the_call_budget_with_no_ssh_left_behind(fresh_ap: Harness, tmp_path: Path) -> None:
    port = fresh_ap.dropbear_port
    fresh_ap.set_knob("hang", True)
    store = trusted_store(tmp_path, fresh_ap, port)
    started = time.monotonic()
    with pytest.raises(ScanTimeoutError, match=r"did not finish within 4 s"):
        scanner(store, timeout=4.0).scan(target(fresh_ap, port))
    assert time.monotonic() - started < 10
    alias = host_key_alias(ORIGIN, "default", MAC)
    leftovers = subprocess.run(["pgrep", "-f", f"HostKeyAlias={alias}"], capture_output=True, text=True)
    assert leftovers.stdout.strip() == ""
    # The access point keeps scanning until its own watchdog (25 s for one attempt) ends the hung scan.
    deadline = time.monotonic() + 40
    while time.monotonic() < deadline and fresh_ap.exec_ap("sh", "-c", "pgrep -f '^sleep 600' || true").stdout.strip():
        time.sleep(1)
    assert fresh_ap.exec_ap("sh", "-c", "pgrep -f '^sleep 600' || true").stdout.strip() == b""


@pytest.mark.parametrize("knob", ["flood", "longline"])
def test_output_caps_cut_the_connection(fresh_ap: Harness, tmp_path: Path, knob: str) -> None:
    port = fresh_ap.dropbear_port
    fresh_ap.set_knob(knob, True)
    with pytest.raises(ScanOutputTooLargeError):
        scanner(trusted_store(tmp_path, fresh_ap, port)).scan(target(fresh_ap, port))


@pytest.mark.parametrize(("knob", "status"), [("fail", BandScanStatus.FAILED), ("empty", BandScanStatus.EMPTY)])
def test_a_scan_that_fails_is_failed_and_one_that_sees_nothing_is_empty(
    fresh_ap: Harness, tmp_path: Path, knob: str, status: BandScanStatus
) -> None:
    port = fresh_ap.dropbear_port
    fresh_ap.set_knob(knob, True)
    result = scanner(trusted_store(tmp_path, fresh_ap, port)).scan(target(fresh_ap, port, attempts=2))
    two = result.band(Band.GHZ_2)
    assert two is not None and two.status is status and two.readings == ()


def test_a_scan_that_prints_part_of_its_list_and_then_fails_is_failed_without_readings(
    fresh_ap: Harness, tmp_path: Path
) -> None:
    port = fresh_ap.dropbear_port
    fresh_ap.set_knob("partialfail", True)
    result = scanner(trusted_store(tmp_path, fresh_ap, port)).scan(target(fresh_ap, port, attempts=2))
    two = result.band(Band.GHZ_2)
    assert two is not None and two.status is BandScanStatus.FAILED and two.readings == ()


def test_a_scan_that_prints_part_of_its_list_and_then_hangs_is_failed_without_readings(
    fresh_ap: Harness, tmp_path: Path
) -> None:
    fresh_ap.set_knob("partialhang", True)
    output = _run_script_over_ssh(fresh_ap, tmp_path, b"SCAN_ATTEMPTS=1\nIFACE_TOGGLE=0\nSCAN_TIMEOUT_S=2\n")
    two = parse_scan_output(output).band(Band.GHZ_2)
    assert two is not None and two.status is BandScanStatus.FAILED and two.readings == ()


def test_a_partial_attempt_after_a_complete_empty_one_leaves_the_band_empty(fresh_ap: Harness, tmp_path: Path) -> None:
    port = fresh_ap.dropbear_port
    fresh_ap.set_knob("empty", True)
    fresh_ap.set_knob("partialfail", True)
    fresh_ap.exec_ap("sh", "-c", "echo 2 >/run/stub/partial-at")
    result = scanner(trusted_store(tmp_path, fresh_ap, port)).scan(target(fresh_ap, port, attempts=2))
    two = result.band(Band.GHZ_2)
    assert two is not None and two.status is BandScanStatus.EMPTY and two.readings == ()


def test_a_partial_attempt_after_a_complete_one_adds_no_readings(fresh_ap: Harness, tmp_path: Path) -> None:
    port = fresh_ap.dropbear_port
    fresh_ap.set_knob("partialfail", True)
    fresh_ap.exec_ap("sh", "-c", "echo 2 >/run/stub/partial-at")
    result = scanner(trusted_store(tmp_path, fresh_ap, port)).scan(target(fresh_ap, port, attempts=2))
    two = result.band(Band.GHZ_2)
    assert two is not None and two.status is BandScanStatus.OK
    assert [r.bssid for r in two.readings] == ["02:00:00:00:00:a1", "02:00:00:00:00:b2", "02:00:00:00:00:c3"]


def test_a_band_whose_ap_interface_is_down_has_no_radio(fresh_ap: Harness, tmp_path: Path) -> None:
    port = fresh_ap.dropbear_port
    fresh_ap.exec_ap("sh", "-c", "rm -f /run/ifstate/ra0.up")
    try:
        result = scanner(trusted_store(tmp_path, fresh_ap, port)).scan(target(fresh_ap, port))
        assert result.band(Band.GHZ_2).status is BandScanStatus.NO_RADIO  # type: ignore[union-attr]
    finally:
        fresh_ap.exec_ap("sh", "-c", ": >/run/ifstate/ra0.up")


def test_trust_on_first_use_against_dropbear_then_a_scan(fresh_ap: Harness, tmp_path: Path) -> None:
    from unifiwifioptimizer.adapters.ssh.hostkeys import Expectation, TrustBasis, select_candidate

    port = fresh_ap.dropbear_port
    candidates = keyscan(fresh_ap.address, port)
    assert len(candidates) >= 2, [c.key_type for c in candidates]
    chosen = select_candidate(candidates, Expectation((), TrustBasis.UNVERIFIED))
    assert chosen.key_type == "ssh-ed25519"
    store = KnownHostsStore(tmp_path / "tofu" / "known_hosts")
    store.add(chosen.entry(host_key_alias(ORIGIN, "default", MAC)))
    assert scanner(store).scan(target(fresh_ap, port)).band(Band.GHZ_2).status is BandScanStatus.OK  # type: ignore[union-attr]


def _run_script_over_ssh(harness: Harness, tmp_path: Path, header: bytes) -> bytes:
    """The tool's exact argv with a custom header: how the remote watchdog is exercised within seconds."""
    port = harness.dropbear_port
    store = trusted_store(tmp_path, harness, port)
    invocation = build_invocation(
        target(harness, port), store.path, ASKPASS, load_script(), {"PATH": "/usr/bin:/bin"}, lambda address: True
    )
    completed = subprocess.run(
        list(invocation.argv), input=header + load_script(), capture_output=True, env=dict(invocation.env), timeout=60
    )
    assert completed.returncode == 0, completed.stderr
    return completed.stdout


def test_the_remote_watchdog_ends_a_stuck_iw_scan_busybox_timeout(fresh_ap: Harness, tmp_path: Path) -> None:
    fresh_ap.set_knob("hang", True)
    started = time.monotonic()
    output = _run_script_over_ssh(fresh_ap, tmp_path, b"SCAN_ATTEMPTS=1\nIFACE_TOGGLE=0\nSCAN_TIMEOUT_S=2\n")
    assert time.monotonic() - started < 20
    result = parse_scan_output(output)
    assert result.band(Band.GHZ_2).status is BandScanStatus.FAILED and result.meta.watchdog == "timeout"  # type: ignore[union-attr]
    assert fresh_ap.exec_ap("sh", "-c", "pgrep -f '^sleep 600' || true").stdout.strip() == b""


def test_the_remote_watchdog_falls_back_to_a_background_watcher_without_the_timeout_applet(fresh_ap: Harness) -> None:
    fresh_ap.set_knob("hang", True)
    started = time.monotonic()
    completed = fresh_ap.exec_ap(
        "env",
        "PATH=/opt/notimeout/bin",
        "sh",
        "-s",
        stdin=b"SCAN_ATTEMPTS=1\nIFACE_TOGGLE=0\nSCAN_TIMEOUT_S=2\n" + load_script(),
    )
    assert time.monotonic() - started < 20
    result = parse_scan_output(completed.stdout)
    assert result.meta.watchdog == "watcher" and result.band(Band.GHZ_2).status is BandScanStatus.FAILED  # type: ignore[union-attr]
    time.sleep(0.5)
    # Neither the hung scan nor the watcher's own sleep may outlive the script.
    assert fresh_ap.exec_ap("sh", "-c", "pgrep -f '^sleep 600' || true").stdout.strip() == b""
    assert fresh_ap.exec_ap("sh", "-c", "pgrep -f '^sleep 2$' || true").stdout.strip() == b""


def test_an_old_busybox_timeout_syntax_is_detected_and_the_watcher_takes_over(fresh_ap: Harness) -> None:
    # /opt/oldtimeout/bin has a `timeout` that only knows `-t SECS`; `timeout 1 true` fails there, so the
    # script must not trust the applet's presence alone.
    fresh_ap.set_knob("hang", True)
    started = time.monotonic()
    completed = fresh_ap.exec_ap(
        "env",
        "PATH=/opt/oldtimeout/bin",
        "sh",
        "-s",
        stdin=b"SCAN_ATTEMPTS=1\nIFACE_TOGGLE=0\nSCAN_TIMEOUT_S=2\n" + load_script(),
    )
    assert time.monotonic() - started < 20
    result = parse_scan_output(completed.stdout)
    assert result.meta.watchdog == "watcher" and result.band(Band.GHZ_2).status is BandScanStatus.FAILED  # type: ignore[union-attr]


@pytest.mark.parametrize("path", ["/opt/notimeout/bin", "/opt/oldtimeout/bin"])
def test_the_watcher_lets_a_healthy_scan_finish_and_leaves_no_sleep_behind(fresh_ap: Harness, path: str) -> None:
    completed = fresh_ap.exec_ap(
        "env", f"PATH={path}", "sh", "-s", stdin=b"SCAN_ATTEMPTS=1\nIFACE_TOGGLE=0\nSCAN_TIMEOUT_S=30\n" + load_script()
    )
    result = parse_scan_output(completed.stdout)
    two = result.band(Band.GHZ_2)
    # A `timeout` that does not take `SECS PROG` would run the seconds as the program and fail the band.
    assert two is not None and two.status is BandScanStatus.OK
    assert [r.bssid for r in two.readings] == ["02:00:00:00:00:a1", "02:00:00:00:00:b2", "02:00:00:00:00:c3"]
    assert result.meta.watchdog == "watcher"
    # The watcher must kill its own sleep when the scan returns first, not let it run for the full bound.
    assert fresh_ap.exec_ap("sh", "-c", "pgrep -f '^sleep 30$' || true").stdout.strip() == b""


def test_the_watcher_keeps_the_scan_status_apart_from_its_own_kill(fresh_ap: Harness) -> None:
    fresh_ap.set_knob("empty", True)
    completed = fresh_ap.exec_ap(
        "env",
        "PATH=/opt/notimeout/bin",
        "sh",
        "-s",
        stdin=b"SCAN_ATTEMPTS=1\nIFACE_TOGGLE=0\nSCAN_TIMEOUT_S=30\n" + load_script(),
    )
    result = parse_scan_output(completed.stdout)
    assert result.meta.watchdog == "watcher" and result.band(Band.GHZ_2).status is BandScanStatus.EMPTY  # type: ignore[union-attr]


def test_the_remote_script_is_valid_busybox_ash_and_restores_toggled_interfaces_on_a_signal(fresh_ap: Harness) -> None:
    assert fresh_ap.exec_ap("busybox", "sh", "-n", stdin=load_script()).returncode == 0
    # Toggle on, the 5 GHz scan interface down and its scan hanging: the script brings the interface up,
    # sticks in `iw scan`, receives SIGTERM from the side, and the trap puts the interface down again.
    fresh_ap.set_knob("hang-apclii0", True)
    completed = fresh_ap.exec_ap(
        "sh", "-c", "( sleep 3; pkill -TERM -x sh ) >/dev/null 2>&1 & exec sh -s",
        stdin=b"SCAN_ATTEMPTS=1\nIFACE_TOGGLE=1\nSCAN_TIMEOUT_S=30\n" + load_script(),
        check=False,
    )  # fmt: skip
    assert completed.returncode == 143, completed.stderr
    assert fresh_ap.toggles() == ["apclii0 up", "apclii0 down"]
    assert fresh_ap.exec_ap("sh", "-c", "test -e /run/ifstate/apclii0.up", check=False).returncode == 1


def test_a_vanished_ssh_client_lets_the_pipe_trap_restore_a_toggled_interface(
    fresh_ap: Harness, tmp_path: Path
) -> None:
    # The tool kills ssh at its call budget while the access point is still scanning; the next line the
    # script writes meets a closed channel and SIGPIPE, and the trap puts the toggled interface down. The
    # header shortens the remote watchdog so the write happens within seconds.
    port = fresh_ap.dropbear_port
    fresh_ap.set_knob("hang-apclii0", True)
    store = trusted_store(tmp_path, fresh_ap, port)
    invocation = build_invocation(
        target(fresh_ap, port, toggle=True),
        store.path,
        ASKPASS,
        load_script(),
        {"PATH": "/usr/bin:/bin"},
        lambda a: True,
    )
    stdin = b"SCAN_ATTEMPTS=1\nIFACE_TOGGLE=1\nSCAN_TIMEOUT_S=5\n" + load_script()
    with subprocess.Popen(
        list(invocation.argv),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        env=dict(invocation.env),
    ) as process:
        assert process.stdin is not None and process.stdout is not None
        process.stdin.write(stdin)
        process.stdin.close()
        for line in process.stdout:
            if line.strip() == b"===5GHZ===":
                break
        time.sleep(2)
        assert fresh_ap.toggles() == ["apclii0 up"]
        process.kill()
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline and fresh_ap.toggles() != ["apclii0 up", "apclii0 down"]:
        time.sleep(0.5)
    assert fresh_ap.toggles() == ["apclii0 up", "apclii0 down"]
    assert fresh_ap.exec_ap("sh", "-c", "test -e /run/ifstate/apclii0.up", check=False).returncode == 1


def test_local_fingerprints_agree_with_ssh_keygen(fresh_ap: Harness, tmp_path: Path) -> None:
    for port in (fresh_ap.dropbear_port, fresh_ap.sshd_port):
        for candidate in keyscan(fresh_ap.address, port):
            key_file = tmp_path / f"{port}-{candidate.key_type}.pub"
            key_file.write_text(f"{candidate.key_type} {candidate.key_base64}\n")
            printed = subprocess.run(
                ["ssh-keygen", "-lf", str(key_file)], capture_output=True, text=True, check=True
            ).stdout
            assert candidate.sha256.text in printed
            printed_md5 = subprocess.run(
                ["ssh-keygen", "-E", "md5", "-lf", str(key_file)], capture_output=True, text=True, check=True
            ).stdout
            assert candidate.md5.text in printed_md5


def test_the_store_entry_is_what_openssh_reads(fresh_ap: Harness, tmp_path: Path) -> None:
    port = fresh_ap.dropbear_port
    store = trusted_store(tmp_path, fresh_ap, port)
    (entry,) = store.entries()
    assert entry.alias == host_key_alias(ORIGIN, "default", MAC)
    # ssh-keygen -F finds the alias line, which is what StrictHostKeyChecking=yes matches against.
    found = subprocess.run(
        ["ssh-keygen", "-F", entry.alias, "-f", str(store.path)], capture_output=True, text=True
    ).stdout
    assert entry.key_base64 in found
