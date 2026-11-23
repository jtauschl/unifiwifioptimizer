"""A refusal of the trust step carries a kind, and one table gives each kind its next step: the table is complete,
every producer raises the kind that names what the person does next, and the result line carries the step."""

import dataclasses
import re
from collections.abc import Sequence
from ipaddress import ip_address

import pytest

from tests.unit.app.test_trust_decision import (
    ALIAS,
    NO_EXPECTATION,
    STORE,
    Memory,
    Scans,
    cand,
    controller_says,
    held,
    pin_says,
    plan,
    subject,
)
from unifiwifioptimizer.adapters.ssh.hostkeys import HostKeyCandidate, KnownHostEntry, expected_fingerprint
from unifiwifioptimizer.app.trust import (
    Refused,
    TrustOutcome,
    TrustPolicy,
    TrustResult,
    apply_decision,
    inspect_access_point,
    trust_step,
)
from unifiwifioptimizer.cli.main import _result_line
from unifiwifioptimizer.domain.errors import HostKeyTrustError
from unifiwifioptimizer.domain.hostkeys import TRUST_ADVICE, TrustRefusalKind
from unifiwifioptimizer.domain.scan import FAILURE_ADVICE, ScanFailureKind

K = TrustRefusalKind

# The sentences, written out once more on purpose: swapping two table entries must fail a test.
EXPECTED_STEPS = {
    K.ADDRESS_NOT_USED: (
        "an address outside the private ranges needs `sites.default.ssh.allow_public_ap_addresses: true`; "
        "loopback, multicast, reserved and unspecified addresses are never used"
    ),
    K.FINGERPRINT_FORM: (
        "report it with the controller version; this access point cannot be trusted or re-trusted until the "
        "controller reports a SHA-256 or an MD5 fingerprint, or none (a pin does not override it); a key already "
        "stored keeps working"
    ),
    K.NO_KEY_OFFERED: "check that the access point answers SSH on port 22 at the address the controller reports",
    K.KEYSCAN_TIMEOUT: "run again; report it with the access point's firmware version when it repeats",
    K.KEYSCAN_TOO_MANY: "report it with the access point's firmware version",
    K.KEY_MISMATCH_PIN: (
        "the pin is wrong (a typo, another access point's fingerprint) or the access point was reset or re-adopted; "
        "if none of these holds, someone else may answer at this address: store nothing; correct "
        "`sites.default.ssh.host_keys` only with a fingerprint from a source other than this tool"
    ),
    K.KEY_MISMATCH_CONTROLLER: (
        "the access point was reset or re-adopted, or the controller's value is stale; this key is stored only once "
        "the controller reports it; if none of these holds, someone else may answer at this address: store nothing"
    ),
    K.STORED_KEY_REJECTED_PIN: (
        "the stored key still answers and the scan keeps using it; the pin in `sites.default.ssh.host_keys` names "
        "another key: check that value (a typo, another access point's fingerprint) before you change anything"
    ),
    K.STORED_KEY_REJECTED_CONTROLLER: (
        "the stored key still answers and the scan keeps using it; the fingerprint the controller reports names "
        "another key: check that value (stale, another device) before you change anything"
    ),
    K.SOURCES_DISAGREE: (
        "compare both values with the access point's key from a source other than this tool; correct "
        "`sites.default.ssh.host_keys` when the pin is wrong, otherwise find out why the controller reports another "
        "key (reset, re-adoption); the two may also name different key types of the same access point: then pin the "
        "key the controller reports"
    ),
    K.UNUSABLE_KEYS: "report it with the access point's firmware version",
    K.SEVERAL_STORED_LINES: (
        "delete every line of that alias from that file (OpenSSH trusts any of them), then run "
        "`trust-host-keys --site default`, which handles the key as one not yet stored"
    ),
    K.STORE_CHANGED: (
        "the store changed while this access point was being handled (another run of the tool, or an edit by hand); "
        "run again"
    ),
    K.NOT_ON_CONTROLLER_NAMED: (
        "check the spelling; `unifiwifioptimizer site default` lists the names (quote a name with blanks)"
    ),
    K.NOT_ON_CONTROLLER_CONFIGURED: (
        "the name under `sites.default.neighbors` is not on the controller; `unifiwifioptimizer site default` lists "
        "the names"
    ),
}


def test_every_kind_has_a_step_and_the_only_placeholder_is_the_site() -> None:
    assert set(TRUST_ADVICE) == set(K) == set(EXPECTED_STEPS)
    for kind, step in TRUST_ADVICE.items():
        assert set(re.findall(r"\{(\w+)\}", step)) <= {"site", "options"}, kind
        assert trust_step(kind, "default") == EXPECTED_STEPS[kind], kind


def test_a_step_the_scan_side_has_too_is_the_same_text() -> None:
    assert TRUST_ADVICE[K.ADDRESS_NOT_USED] == FAILURE_ADVICE[ScanFailureKind.ADDRESS_REFUSED].next_step
    assert TRUST_ADVICE[K.NO_KEY_OFFERED] == FAILURE_ADVICE[ScanFailureKind.TRANSPORT].next_step
    assert TRUST_ADVICE[K.KEYSCAN_TIMEOUT] == FAILURE_ADVICE[ScanFailureKind.TIMEOUT].next_step


# --- plan_trust: the refusal of rule 3 is told apart by what the person does next -----------------------------------


def refusal(decision: object) -> Refused:
    assert isinstance(decision, Refused), decision
    return decision


def test_rule_1_names_the_alias_and_the_store_in_the_reason() -> None:
    refused = refusal(plan([held(cand(1)), held(cand(2))], [cand(1)], NO_EXPECTATION))
    assert refused.kind is K.SEVERAL_STORED_LINES
    assert refused.reason == f"several entries are stored for this access point (alias {ALIAS}) in {STORE}"


def test_rule_2_nothing_offered_is_a_missing_key() -> None:
    assert refusal(plan([], [], NO_EXPECTATION)).kind is K.NO_KEY_OFFERED


@pytest.mark.parametrize(
    ("expectation", "kind"),
    [(controller_says(cand(2)), K.KEY_MISMATCH_CONTROLLER), (pin_says(cand(2)), K.KEY_MISMATCH_PIN)],
)
def test_rule_3_a_key_that_neither_source_names_is_a_mismatch_by_basis(
    expectation: object, kind: TrustRefusalKind
) -> None:
    refused = refusal(plan([], [cand(1)], expectation))  # type: ignore[arg-type]
    assert refused.kind is kind
    assert refused.reason == f"none of the 1 offered host keys matches the {refused.basis}"
    assert refusal(plan([held(cand(3))], [cand(1)], expectation)).kind is kind  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("expectation", "kind"),
    [
        (controller_says(cand(2)), K.STORED_KEY_REJECTED_CONTROLLER),
        (pin_says(cand(2)), K.STORED_KEY_REJECTED_PIN),
    ],
)
def test_rule_3_a_stored_key_that_is_still_offered_and_rejected_names_the_value_to_check(
    expectation: object, kind: TrustRefusalKind
) -> None:
    stored = cand(1)
    assert refusal(plan([held(stored)], [stored], expectation)).kind is kind  # type: ignore[arg-type]


def test_rule_3_a_pin_that_matches_and_a_controller_md5_that_does_not_are_two_sources_that_disagree() -> None:
    a, b = cand(1), cand(2)
    expectation = expected_fingerprint(a.sha256.digest, b.md5)
    first = refusal(plan([], [a], expectation))
    assert first.kind is K.SOURCES_DISAGREE
    assert (
        first.reason
        == f"the key matching the configuration pin {a.sha256.text} does not match the controller's {b.md5.text}"
    )
    # With the stored key being the one that matches the pin the text would be false, so the order matters.
    assert refusal(plan([held(a)], [a], expectation)).kind is K.SOURCES_DISAGREE


def test_rule_3_the_mirror_case_the_controller_names_an_offered_key_that_the_pin_does_not() -> None:
    a, b = cand(1), cand(2)
    expectation = expected_fingerprint(a.sha256.digest, b.md5)
    mirror = refusal(plan([], [b], expectation))
    assert mirror.kind is K.SOURCES_DISAGREE
    assert mirror.reason == (
        f"no offered key matches the configuration pin {a.sha256.text}; the controller's {b.md5.text} matches the "
        f"offered {b.sha256.text}"
    )
    assert refusal(plan([held(b)], [b], expectation)).kind is K.SOURCES_DISAGREE
    nothing = refusal(plan([], [cand(3)], expectation))
    assert nothing.kind is K.KEY_MISMATCH_PIN


def test_a_case_that_passes_today_still_passes() -> None:
    a = cand(1)
    both = expected_fingerprint(a.sha256.digest, a.md5)
    assert not isinstance(plan([], [a], both), Refused)


# --- the result of a refusal carries the final step ----------------------------------------------------------------


def result_of(decision_subject: object, store: Memory, scan: object, *, answer: bool = False) -> TrustResult:
    policy = TrustPolicy(assume_yes=False, accept_unverified=False, confirm=lambda p: answer)
    inspected = inspect_access_point(decision_subject, store, scan)  # type: ignore[arg-type]
    return apply_decision(decision_subject, inspected, store, policy)  # type: ignore[arg-type]


def test_an_address_the_tool_does_not_use_is_refused_with_the_step_of_the_scan_side() -> None:
    public = dataclasses.replace(subject(), address=ip_address("8.8.8.8"))
    result = result_of(public, Memory(), Scans([], []))
    assert result.outcome is TrustOutcome.FAILED and result.basis is None
    assert _result_line(result) == (
        f"AP-1: failed address 8.8.8.8 is not used for SSH; {EXPECTED_STEPS[K.ADDRESS_NOT_USED]}"
    )


def test_an_unknown_controller_fingerprint_form_is_quoted_and_names_the_step() -> None:
    odd = dataclasses.replace(subject(), controller_fingerprint='not a "fingerprint"')
    result = result_of(odd, Memory(), Scans([], []))
    assert _result_line(result) == (
        'AP-1: failed the controller reports a host-key fingerprint in an unknown form: "not a \\"fingerprint\\""; '
        f"{EXPECTED_STEPS[K.FINGERPRINT_FORM]}"
    )


def test_no_key_offered_names_the_basis_and_the_step() -> None:
    result = result_of(subject(), Memory(), Scans([], []))
    assert _result_line(result) == (
        f"AP-1: failed (trust on first use (unverified)) no host key offered; {EXPECTED_STEPS[K.NO_KEY_OFFERED]}"
    )


def test_a_keyscan_that_ran_out_of_time_names_the_step_without_a_basis() -> None:
    def timed_out(address: object, port: int, key_type: str | None) -> Sequence[HostKeyCandidate]:
        raise HostKeyTrustError(K.KEYSCAN_TIMEOUT, "ssh-keyscan did not finish within 30 s")

    result = result_of(subject(), Memory(), timed_out)
    assert _result_line(result) == (
        f"AP-1: failed ssh-keyscan did not finish within 30 s; {EXPECTED_STEPS[K.KEYSCAN_TIMEOUT]}"
    )


def test_a_mismatch_with_the_controller_names_the_basis_the_reason_and_the_step() -> None:
    named = dataclasses.replace(subject(), controller_fingerprint=cand(2).sha256.text)
    result = result_of(named, Memory(), Scans([], [cand(1)]))
    assert _result_line(result) == (
        "AP-1: failed (controller fingerprint) none of the 1 offered host keys matches the controller fingerprint; "
        f"{EXPECTED_STEPS[K.KEY_MISMATCH_CONTROLLER]}"
    )


def test_a_stored_key_that_still_answers_is_not_called_a_mismatch() -> None:
    stored = cand(1)
    named = dataclasses.replace(subject(), controller_fingerprint=cand(2).sha256.text)
    result = result_of(named, Memory([held(stored)]), Scans([], [stored]))
    assert result.next_step == EXPECTED_STEPS[K.STORED_KEY_REJECTED_CONTROLLER]


def test_a_pin_that_the_controller_contradicts_is_refused_before_any_scan_with_both_values() -> None:
    pinned = dataclasses.replace(
        subject(), config_pin=cand(1).sha256.digest, controller_fingerprint=cand(2).sha256.text
    )
    scan = Scans([], [])
    result = result_of(pinned, Memory(), scan)
    assert scan.calls == []
    assert _result_line(result) == (
        f"AP-1: failed the configured host-key pin {cand(1).sha256.text} and the fingerprint the controller "
        f"reports {cand(2).sha256.text} differ; {EXPECTED_STEPS[K.SOURCES_DISAGREE]}"
    )


def test_several_stored_lines_name_the_alias_and_the_file() -> None:
    result = result_of(subject(), Memory([held(cand(1)), held(cand(2))]), Scans([], [cand(1)]))
    assert _result_line(result) == (
        f"AP-1: failed (trust on first use (unverified)) several entries are stored for this access point "
        f"(alias {ALIAS}) in {STORE}; {EXPECTED_STEPS[K.SEVERAL_STORED_LINES]}"
    )


@pytest.mark.parametrize(
    ("raised", "step_kind"),
    [
        (HostKeyTrustError(K.STORE_CHANGED, "the stored key for alias A changed since it was shown"), K.STORE_CHANGED),
        (HostKeyTrustError(K.SEVERAL_STORED_LINES, "2 entries are stored for alias A in /f"), K.SEVERAL_STORED_LINES),
    ],
)
def test_a_store_that_refuses_the_write_names_the_step_of_its_kind(
    raised: HostKeyTrustError, step_kind: TrustRefusalKind
) -> None:
    class Refusing(Memory):
        def replace(self, entry: KnownHostEntry, expected_old: KnownHostEntry) -> None:
            raise raised

    store = Refusing([held(cand(1))])
    result = result_of(subject(), store, Scans([], [cand(2)]), answer=True)
    assert result.outcome is TrustOutcome.FAILED
    assert result.next_step == EXPECTED_STEPS[step_kind]


def test_two_genuine_keys_of_one_access_point_say_so_and_a_pin_on_the_controllers_key_passes() -> None:
    ed, ecdsa = cand(1, "ssh-ed25519"), cand(2, "ecdsa-sha2-nistp256")
    expectation = expected_fingerprint(ed.sha256.digest, ecdsa.md5)
    refused = refusal(plan([], [ed, ecdsa], expectation))
    assert refused.kind is K.SOURCES_DISAGREE
    assert refused.reason == (
        f"the key matching the configuration pin {ed.sha256.text} does not match the controller's {ecdsa.md5.text}; "
        f"the controller's {ecdsa.md5.text} matches the offered ecdsa-sha2-nistp256 {ecdsa.sha256.text}"
    )
    assert "pin the key the controller reports" in TRUST_ADVICE[K.SOURCES_DISAGREE]
    # What the step tells the person to do: a pin on the controller's key satisfies both.
    assert not isinstance(plan([], [ed, ecdsa], expected_fingerprint(ecdsa.sha256.digest, ecdsa.md5)), Refused)


def test_a_pin_and_a_controller_md5_that_both_match_nothing_are_both_named_in_the_reason() -> None:
    expectation = expected_fingerprint(cand(1).sha256.digest, cand(3).md5)
    refused = refusal(plan([], [cand(2)], expectation))
    assert refused.kind is K.KEY_MISMATCH_PIN
    assert refused.reason == (
        f"none of the 1 offered host keys matches the configuration pin or the controller's {cand(3).md5.text}"
    )


def test_the_unusable_key_kinds_of_the_helper_reach_the_result_through_plan_trust() -> None:
    a = cand(1)
    assert refusal(plan([], [a, a], pin_says(a))).kind is K.UNUSABLE_KEYS
    assert refusal(plan([], [cand(1), cand(2)], NO_EXPECTATION)).kind is K.UNUSABLE_KEYS


def test_the_step_names_the_site_of_the_subject_on_every_producer() -> None:
    branch = dataclasses.replace(subject(), site_id="branch", config_pin=cand(2).sha256.digest)
    mismatch = result_of(branch, Memory(), Scans([], [cand(1)]))
    assert "`sites.branch.ssh.host_keys`" in mismatch.next_step

    class Refusing(Memory):
        def replace(self, entry: KnownHostEntry, expected_old: KnownHostEntry) -> None:
            raise HostKeyTrustError(K.SEVERAL_STORED_LINES, "2 entries are stored for alias A in /f")

    written = result_of(
        dataclasses.replace(subject(), site_id="branch"), Refusing([held(cand(1))]), Scans([], [cand(2)]), answer=True
    )
    assert "`trust-host-keys --site branch`" in written.next_step


def test_the_step_that_names_the_command_repeats_the_options_of_the_invocation() -> None:
    options = " --known-hosts='/Volumes/Temp HD/kh'"
    assert trust_step(K.SEVERAL_STORED_LINES, "default", options) == (
        "delete every line of that alias from that file (OpenSSH trusts any of them), then run "
        "`trust-host-keys --site default --known-hosts='/Volumes/Temp HD/kh'`, which handles the key as one not yet "
        "stored"
    )
    for kind in K:
        if kind is not K.SEVERAL_STORED_LINES:
            assert trust_step(kind, "default", options) == EXPECTED_STEPS[kind], kind


def test_the_options_reach_the_result_of_a_store_that_has_several_lines_through_the_policy() -> None:
    policy = TrustPolicy(
        assume_yes=False, accept_unverified=False, confirm=lambda p: False, command_options=" --known-hosts=/kh"
    )
    store = Memory([held(cand(1)), held(cand(2))])
    result = apply_decision(subject(), inspect_access_point(subject(), store, Scans([], [cand(1)])), store, policy)
    assert "`trust-host-keys --site default --known-hosts=/kh`" in result.next_step


def test_the_options_reach_the_step_of_a_store_that_refuses_the_write() -> None:
    class Refusing(Memory):
        def replace(self, entry: KnownHostEntry, expected_old: KnownHostEntry) -> None:
            raise HostKeyTrustError(K.SEVERAL_STORED_LINES, "2 entries are stored for alias A in /f")

    policy = TrustPolicy(
        assume_yes=False, accept_unverified=False, confirm=lambda p: True, command_options=" --known-hosts=/kh"
    )
    store = Refusing([held(cand(1))])
    result = apply_decision(subject(), inspect_access_point(subject(), store, Scans([], [cand(2)])), store, policy)
    assert "`trust-host-keys --site default --known-hosts=/kh`" in result.next_step
