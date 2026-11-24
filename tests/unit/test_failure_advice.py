"""What a failed scan says: one table gives the words and the next step of every kind, and every reader prints them,
never the enum value."""

import io
import json
import re
from dataclasses import replace
from ipaddress import ip_address
from pathlib import Path

import pytest

from tests.unit.adapters.test_openssh import ASKPASS, ENVIRON, SCRIPT, target
from tests.unit.analysis.builders import golden_input, scan_pass
from tests.unit.printed import PLAIN, PLAIN_STEPS, given
from unifiwifioptimizer.adapters.ssh.openssh import build_invocation, classify_exit
from unifiwifioptimizer.analysis.site_analyzer import analyze_site
from unifiwifioptimizer.app.scanning import failure_kind
from unifiwifioptimizer.cli.progress import MAX_CAUSE_CHARS, StderrProgress
from unifiwifioptimizer.domain.commands import PrintedCommands
from unifiwifioptimizer.domain.errors import (
    AddressRefusedError,
    HostKeyMismatchError,
    HostKeyUnknownError,
    RemoteScriptError,
    ScanError,
    ScanOutputTooLargeError,
    ScanParseError,
    ScanTimeoutError,
    SshAuthenticationError,
)
from unifiwifioptimizer.domain.scan import (
    FAILURE_ADVICE,
    HOST_KEY_KINDS,
    ScanFailure,
    ScanFailureKind,
    SiteScan,
    TrustStepContext,
    ap_said,
    failure_step,
    failure_words,
)
from unifiwifioptimizer.report.json import render_json
from unifiwifioptimizer.report.safe_text import safe_text
from unifiwifioptimizer.report.text import LINE_MAX, render_overview, render_report

# The sentences, written out once more on purpose: swapping two table entries must fail a test.
EXPECTED: dict[ScanFailureKind, tuple[str, str]] = {
    ScanFailureKind.HOST_KEY_UNKNOWN: (
        "host key not stored",
        "`unifiwifioptimizer trust-host-keys --site default`, or run again in a terminal",
    ),
    ScanFailureKind.HOST_KEY_MISMATCH: (
        "changed host key",
        "find out why the key changed (reset, re-adoption), then `unifiwifioptimizer trust-host-keys --site default`",
    ),
    ScanFailureKind.AUTHENTICATION: (
        "SSH login refused",
        "check `sites.default.ssh.auth`: `controller` uses the device SSH settings of the controller, `password` and "
        "`key` those of the configuration (`password` or `UNIFI_SSH_PASSWORD`; `key_file` or the SSH agent)",
    ),
    ScanFailureKind.TIMEOUT: (
        "scan timed out",
        "run again; report it with the access point's firmware version when it repeats",
    ),
    ScanFailureKind.OUTPUT_TOO_LARGE: (
        "scan output too large",
        "report it with the access point's firmware version",
    ),
    ScanFailureKind.TRANSPORT: (
        "SSH connection failed",
        "check that the access point answers SSH on port 22 at the address the controller reports",
    ),
    ScanFailureKind.REMOTE_SCRIPT: ("scan script failed", "report it with the access point's firmware version"),
    ScanFailureKind.UNPARSABLE_OUTPUT: (
        "scan output not understood",
        "report it with the access point's firmware version",
    ),
    ScanFailureKind.ADDRESS_REFUSED: (
        "address not used for SSH",
        "an address outside the private ranges needs `sites.default.ssh.allow_public_ap_addresses: true`; loopback, "
        "multicast, reserved and unspecified addresses are never used",
    ),
}
DETAIL_KINDS = {
    ScanFailureKind.AUTHENTICATION,
    ScanFailureKind.TRANSPORT,
    ScanFailureKind.REMOTE_SCRIPT,
    ScanFailureKind.UNPARSABLE_OUTPUT,
    ScanFailureKind.ADDRESS_REFUSED,
}


def test_every_kind_has_words_and_a_next_step_and_the_placeholders_are_the_site_and_the_trust_command() -> None:
    assert set(FAILURE_ADVICE) == set(ScanFailureKind) == set(EXPECTED)
    for kind, advice in FAILURE_ADVICE.items():
        assert advice.words and advice.next_step
        assert set(re.findall(r"\{(\w+)\}", advice.next_step)) <= {"site", "trust"}, kind
        assert advice.show_detail is (kind in DETAIL_KINDS), kind
        assert (advice.words, advice.step("default", PLAIN)) == EXPECTED[kind], kind


def test_several_kinds_are_named_in_declaration_order_once_each() -> None:
    both = [
        ScanFailureKind.TIMEOUT,
        ScanFailureKind.HOST_KEY_MISMATCH,
        ScanFailureKind.HOST_KEY_UNKNOWN,
        ScanFailureKind.TIMEOUT,
    ]
    # Declaration order, not alphabetical order of the words ("changed" would sort before "host").
    assert failure_words(both) == "host key not stored, changed host key, scan timed out"


def failing(inp, kind: ScanFailureKind, ap: str = "AP-1", passes: int = 3):  # type: ignore[no-untyped-def]
    assert isinstance(inp.scan, SiteScan)
    broken = tuple(ScanFailure(kind=kind, detail="") for _ in range(passes))
    scans = tuple(replace(s, passes=broken) if s.ap_name == ap else s for s in inp.scan.scans)
    return replace(inp, scan=replace(inp.scan, scans=scans))


@pytest.mark.parametrize("kind", list(ScanFailureKind))
def test_every_reader_prints_the_words_and_the_step_once_and_never_the_enum_value(kind: ScanFailureKind) -> None:
    words, step = EXPECTED[kind]
    report = analyze_site(failing(golden_input(), kind))
    overview = render_overview(report, width=None, steps=PLAIN_STEPS)
    details = render_report(report, width=None, steps=PLAIN_STEPS)
    finding = f"* AP-1: every scan pass failed: {words}"
    assert finding in overview
    assert f"Scan failed on AP-1: 3 pass(es) ({words})." in overview
    assert f"  ! AP-1: 3 failed pass(es), 0 successful ({words})" in details
    for text in (overview, details):
        assert kind.value not in text
        assert text.count(f"{words}: {step}") == 1, (kind, text.count(f"{words}: {step}"))
    # The finding is clipped at `LINE_MAX`; it carries the words only, so no kind loses its end.
    assert len(finding) < LINE_MAX


def test_two_access_points_with_the_same_kind_share_one_step() -> None:
    inp = failing(
        failing(golden_input(), ScanFailureKind.HOST_KEY_UNKNOWN, "AP-1"), ScanFailureKind.HOST_KEY_UNKNOWN, "AP-2"
    )
    report = analyze_site(inp)
    sentence = "host key not stored: `unifiwifioptimizer trust-host-keys --site default`"
    assert render_overview(report, width=None, steps=PLAIN_STEPS).count(sentence) == 1
    assert render_report(report, width=None, steps=PLAIN_STEPS).count(sentence) == 1


def test_a_long_site_id_folds_the_step_without_losing_a_word() -> None:
    site = "s" * 64
    for kind in (ScanFailureKind.AUTHENTICATION, ScanFailureKind.ADDRESS_REFUSED, ScanFailureKind.HOST_KEY_MISMATCH):
        report = replace(analyze_site(failing(golden_input(), kind)), site_id=site)
        words, step = EXPECTED[kind][0], FAILURE_ADVICE[kind].step(site, PLAIN)
        for text in (render_overview(report, steps=PLAIN_STEPS), render_report(report, steps=PLAIN_STEPS)):
            assert f"{words}: {step}" in " ".join(text.split()), kind


def test_a_partial_failure_names_the_words_and_two_kinds_stay_in_declaration_order() -> None:
    inp = golden_input()
    assert isinstance(inp.scan, SiteScan)
    mixed = (
        ScanFailure(kind=ScanFailureKind.TIMEOUT, detail=""),
        scan_pass(),
        ScanFailure(kind=ScanFailureKind.HOST_KEY_MISMATCH, detail=""),
    )
    scans = tuple(replace(s, passes=mixed) if s.ap_name == "AP-1" else s for s in inp.scan.scans)
    report = analyze_site(replace(inp, scan=replace(inp.scan, scans=scans)))
    details = render_report(report, width=None, steps=PLAIN_STEPS)
    assert (
        "2 of 3 passes failed (changed host key, scan timed out); the readings come from the successful passes"
        in details
    )
    assert details.index("changed host key: ") < details.index("scan timed out: ")


def test_the_json_keeps_the_enum_values() -> None:
    report = analyze_site(failing(golden_input(), ScanFailureKind.HOST_KEY_UNKNOWN))
    document = json.loads(render_json([report]))
    assert document["sites"][0]["scan"]["failures_by_ap"]["AP-1"] == ["host_key_unknown"] * 3


def test_the_host_key_failures_per_kind_come_from_the_failed_passes_in_declaration_order() -> None:
    inp = failing(golden_input(), ScanFailureKind.HOST_KEY_MISMATCH, "AP-2")
    inp = failing(inp, ScanFailureKind.HOST_KEY_UNKNOWN, "AP-1")
    inp = failing(inp, ScanFailureKind.TRANSPORT, "AP-3")
    report = analyze_site(inp)
    assert list(report.scan.host_key_failures.items()) == [
        (ScanFailureKind.HOST_KEY_UNKNOWN, 1),
        (ScanFailureKind.HOST_KEY_MISMATCH, 1),
    ]
    assert report.host_key_failed_ap_count == 2 and set(report.scan.host_key_failures) <= HOST_KEY_KINDS
    assert analyze_site(golden_input()).scan.host_key_failures == {}


def test_an_access_point_with_both_host_key_kinds_counts_once_as_failed() -> None:
    inp = golden_input()
    assert isinstance(inp.scan, SiteScan)
    both = (
        ScanFailure(kind=ScanFailureKind.HOST_KEY_UNKNOWN, detail=""),
        ScanFailure(kind=ScanFailureKind.HOST_KEY_MISMATCH, detail=""),
        ScanFailure(kind=ScanFailureKind.HOST_KEY_UNKNOWN, detail=""),
    )
    scans = tuple(replace(s, passes=both) if s.ap_name == "AP-1" else s for s in inp.scan.scans)
    summary = analyze_site(replace(inp, scan=replace(inp.scan, scans=scans))).scan
    assert summary.host_key_failed_ap_count == 1
    assert summary.host_key_failures == {ScanFailureKind.HOST_KEY_UNKNOWN: 1, ScanFailureKind.HOST_KEY_MISMATCH: 1}


def test_what_an_access_point_said_is_quoted_and_cannot_close_the_quote() -> None:
    assert ap_said("plain") == '"plain"'
    assert ap_said('a" and the tool says: all fine') == r'"a\" and the tool says: all fine"'
    assert ap_said("back\\slash") == '"back\\\\slash"'


def test_the_cause_names_its_origin_and_quotes_only_what_the_access_point_chose() -> None:
    refused = classify_exit(255, b"ssh: connect to host 10.0.0.5 port 22: Connection refused\n", "AP-1")
    assert refused.cause == 'ssh said "ssh: connect to host 10.0.0.5 port 22: Connection refused"'  # type: ignore[attr-defined]
    denied = classify_exit(255, b"user@10.0.0.5: Permission denied (publickey).\n", "AP-1")
    assert isinstance(denied, SshAuthenticationError)
    assert denied.cause == 'ssh said "user@10.0.0.5: Permission denied (publickey)."'
    silent = classify_exit(255, b"", "AP-1")
    assert silent.cause is None  # type: ignore[attr-defined]
    script = classify_exit(3, b'iw: said "no"\n', "AP-1")
    assert isinstance(script, RemoteScriptError)
    assert script.cause == r'exit status 3, script said "iw: said \"no\""'
    assert classify_exit(3, b"", "AP-1").cause == "exit status 3"  # type: ignore[attr-defined]
    assert isinstance(classify_exit(255, b"Host key verification failed.", "AP-1"), HostKeyMismatchError)
    assert HostKeyMismatchError("x").cause is None and ScanTimeoutError("x").cause is None
    assert ScanParseError("section X missing").cause == "section X missing"
    assert AddressRefusedError("m", cause="address 8.8.8.8").cause == "address 8.8.8.8"


def produced(exc: Exception) -> ScanError:
    assert isinstance(exc, ScanError)
    return exc


def refused_address() -> ScanError:
    with pytest.raises(AddressRefusedError) as raised:
        build_invocation(target(address=ip_address("8.8.8.8")), Path("/kh"), ASKPASS, SCRIPT, ENVIRON)
    return raised.value


def producer_cases() -> list[tuple[ScanError, ScanFailureKind, str]]:
    """What the real producers raise, the kind the orchestrator derives and the cause the progress line adds."""
    refused = b"ssh: connect to host 10.0.0.5 port 22: Connection refused\n"
    return [
        (HostKeyUnknownError("m"), ScanFailureKind.HOST_KEY_UNKNOWN, ""),
        (produced(classify_exit(255, b"Host key verification failed.", "AP-1")), ScanFailureKind.HOST_KEY_MISMATCH, ""),
        (
            produced(classify_exit(255, b"Permission denied (publickey).\n", "AP-1")),
            ScanFailureKind.AUTHENTICATION,
            ': ssh said "Permission denied (publickey)."',
        ),
        (ScanTimeoutError("m"), ScanFailureKind.TIMEOUT, ""),
        (ScanOutputTooLargeError("m"), ScanFailureKind.OUTPUT_TOO_LARGE, ""),
        (
            produced(classify_exit(255, refused, "AP-1")),
            ScanFailureKind.TRANSPORT,
            ': ssh said "ssh: connect to host 10.0.0.5 port 22: Connection refused"',
        ),
        (
            produced(classify_exit(3, b"iw: failed\n", "AP-1")),
            ScanFailureKind.REMOTE_SCRIPT,
            ': exit status 3, script said "iw: failed"',
        ),
        (ScanParseError("section ##SCAN5 missing"), ScanFailureKind.UNPARSABLE_OUTPUT, ": section ##SCAN5 missing"),
        (refused_address(), ScanFailureKind.ADDRESS_REFUSED, ": address 8.8.8.8"),
    ]


def test_the_producers_cover_every_kind() -> None:
    assert {kind for _, kind, _ in producer_cases()} == set(ScanFailureKind)


@pytest.mark.parametrize(
    ("error", "kind", "cause"), producer_cases(), ids=lambda value: str(getattr(value, "value", ""))
)
def test_the_progress_line_from_a_real_producer_names_the_words_and_the_cause(
    error: ScanError, kind: ScanFailureKind, cause: str
) -> None:
    assert failure_kind(error) is kind
    out = io.StringIO()
    progress = StderrProgress(out)
    progress.scan_started("AP-1", 0, 3)
    progress.scan_finished("AP-1", ScanFailure(kind=kind, detail=error.cause or ""))
    assert out.getvalue() == f"    AP-1: scan failed ({FAILURE_ADVICE[kind].words}, pass 1/3){cause}\n"


def test_a_long_cause_is_cut_and_a_hostile_one_loses_its_escape_sequences() -> None:
    out = io.StringIO()
    progress = StderrProgress(out)
    progress.scan_started("AP-1", 0, 3)
    progress.scan_finished("AP-1", ScanFailure(kind=ScanFailureKind.UNPARSABLE_OUTPUT, detail="y" * 1000))
    progress.scan_started("AP-1", 1, 3)
    progress.scan_finished("AP-1", ScanFailure(kind=ScanFailureKind.UNPARSABLE_OUTPUT, detail="a\x1b[31mb"))
    long_line, hostile_line = out.getvalue().splitlines()
    assert long_line.endswith(": " + safe_text("y" * 1000, max_chars=MAX_CAUSE_CHARS)) and len(long_line) < 400
    assert hostile_line.endswith(": ab") and "\x1b" not in out.getvalue()


# --- the host-key step depends on the run: whether the gate checked the keys, and the options of the run -----------

BOTH = given(config_file="/etc/uwo/home.yaml", known_hosts="/Volumes/Temp HD/kh")
COMMAND = "`unifiwifioptimizer trust-host-keys --site s`"
COMMAND_BOTH = (
    "`unifiwifioptimizer --config-file=/etc/uwo/home.yaml trust-host-keys --site s --known-hosts='/Volumes/Temp HD/kh'`"
)
GATE = (
    "the host-key lines above say why a key was refused and what to do; a declined key is asked again on the next run"
)
CAUSE = "find out why the key changed (reset, re-adoption)"


@pytest.mark.parametrize(
    ("kind", "gate_ran", "commands", "expected"),
    [
        (ScanFailureKind.HOST_KEY_UNKNOWN, False, PLAIN, f"{COMMAND}, or run again in a terminal"),
        (ScanFailureKind.HOST_KEY_UNKNOWN, False, BOTH, f"{COMMAND_BOTH}, or run again in a terminal"),
        (ScanFailureKind.HOST_KEY_UNKNOWN, True, PLAIN, f"{GATE} in a terminal, or stored with {COMMAND}"),
        (ScanFailureKind.HOST_KEY_UNKNOWN, True, BOTH, f"{GATE} in a terminal, or stored with {COMMAND_BOTH}"),
        (ScanFailureKind.HOST_KEY_MISMATCH, False, PLAIN, f"{CAUSE}, then {COMMAND}"),
        (ScanFailureKind.HOST_KEY_MISMATCH, False, BOTH, f"{CAUSE}, then {COMMAND_BOTH}"),
        (ScanFailureKind.HOST_KEY_MISMATCH, True, PLAIN, f"{CAUSE}; {GATE} in a terminal, or replaced with {COMMAND}"),
        (
            ScanFailureKind.HOST_KEY_MISMATCH, True, BOTH,
            f"{CAUSE}; {GATE} in a terminal, or replaced with {COMMAND_BOTH}",
        ),
    ],
)  # fmt: skip
def test_the_host_key_step_follows_the_gate_and_repeats_the_options_of_the_run(
    kind: ScanFailureKind, gate_ran: bool, commands: PrintedCommands, expected: str
) -> None:
    assert failure_step(kind, "s", TrustStepContext(gate_ran=gate_ran, commands=commands)) == expected


def test_every_other_kind_has_the_table_step_whatever_the_run_was() -> None:
    for kind in set(ScanFailureKind) - HOST_KEY_KINDS:
        for context in (PLAIN_STEPS, TrustStepContext(gate_ran=True, commands=BOTH)):
            assert failure_step(kind, "default", context) == EXPECTED[kind][1], kind


@pytest.mark.parametrize("kind", sorted(HOST_KEY_KINDS))
@pytest.mark.parametrize("gate_ran", [False, True])
def test_the_report_prints_the_step_of_the_run_once_in_the_overview_and_in_the_details(
    kind: ScanFailureKind, gate_ran: bool
) -> None:
    context = TrustStepContext(gate_ran=gate_ran, commands=BOTH)
    report = analyze_site(failing(golden_input(), kind))
    line = f"{FAILURE_ADVICE[kind].words}: {failure_step(kind, 'default', context)}"
    for text in (render_overview(report, width=None, steps=context), render_report(report, width=None, steps=context)):
        assert text.count(line) == 1, (kind, gate_ran)
    default = render_overview(report, width=None, steps=PLAIN_STEPS)
    assert default.count(f"{FAILURE_ADVICE[kind].words}: {failure_step(kind, 'default', PLAIN_STEPS)}") == 1
    assert "--known-hosts" not in default and "--config-file" not in default
