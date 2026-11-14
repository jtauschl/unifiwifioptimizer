"""The trust decision as a pure function, the policy that applies it, and the keyscan fast path."""

import base64
import dataclasses
from collections.abc import Sequence
from ipaddress import ip_address
from pathlib import Path

import pytest

from unifiwifioptimizer.adapters.ssh.hostkeys import (
    Expectation,
    HostKeyCandidate,
    KnownHostEntry,
    KnownHostsWriter,
    TrustBasis,
    expected_fingerprint,
)
from unifiwifioptimizer.app.trust import (
    AlreadyStored,
    Prompt,
    PromptKind,
    Refused,
    Replace,
    StoreNew,
    TrustDecision,
    TrustOutcome,
    TrustPolicy,
    TrustSubject,
    apply_decision,
    check_host_keys,
    inspect_access_point,
    plan_trust,
)
from unifiwifioptimizer.domain.errors import HostKeyTrustError
from unifiwifioptimizer.domain.hostkeys import key_fingerprints

ALIAS = "uwo-" + "0" * 32
ED = "ssh-ed25519"
ECDSA = "ecdsa-sha2-nistp256"


def cand(seed: int, key_type: str = ED) -> HostKeyCandidate:
    blob = b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00 " + bytes([seed]) * 32
    b64 = base64.b64encode(blob).decode()
    sha, md5 = key_fingerprints(b64)
    return HostKeyCandidate(key_type, b64, sha, md5)


def held(c: HostKeyCandidate) -> KnownHostEntry:
    return c.entry(ALIAS)


NO_EXPECTATION = expected_fingerprint(None, None)


def controller_says(c: HostKeyCandidate) -> Expectation:
    return expected_fingerprint(None, c.sha256)


def pin_says(c: HostKeyCandidate) -> Expectation:
    return expected_fingerprint(c.sha256.digest, None)


class Memory(KnownHostsWriter):
    def __init__(self, rows: Sequence[KnownHostEntry] = ()) -> None:
        super().__init__(Path("/state/known_hosts"))
        self.rows = list(rows)
        self.writes: list[str] = []

    def entries(self) -> tuple[KnownHostEntry, ...]:
        return tuple(self.rows)

    def add(self, entry: KnownHostEntry) -> None:
        self.writes.append("add")
        self.rows.append(entry)

    def replace(self, entry: KnownHostEntry, expected_old: KnownHostEntry) -> None:
        assert [e for e in self.rows if e.alias == entry.alias] == [expected_old]
        self.writes.append("replace")
        self.rows = [entry if e.alias == entry.alias else e for e in self.rows]


# --- plan_trust: one test per rule of the rank ---------------------------------------------------------------


def test_rule_1_several_stored_lines_are_refused() -> None:
    decision = plan_trust([held(cand(1)), held(cand(2))], [cand(1)], NO_EXPECTATION)
    assert isinstance(decision, Refused) and "several entries" in decision.reason


def test_rule_2_nothing_offered_is_refused() -> None:
    assert plan_trust([], [], NO_EXPECTATION) == Refused("no host key offered", TrustBasis.UNVERIFIED)


@pytest.mark.security("T8")
def test_rule_3_a_contradicting_expectation_is_refused_even_when_the_stored_key_still_works() -> None:
    stored, other = cand(1), cand(2)
    decision = plan_trust([held(stored)], [stored], controller_says(other))
    assert isinstance(decision, Refused) and "matches the controller fingerprint" in decision.reason
    assert isinstance(plan_trust([], [stored], pin_says(other)), Refused)


def test_rule_4_a_stored_key_that_is_still_offered_needs_nothing_even_when_the_choice_would_be_ambiguous() -> None:
    stored = cand(1)
    two_of_one_type = [stored, cand(2)]
    assert plan_trust([held(stored)], two_of_one_type, NO_EXPECTATION) == AlreadyStored(
        stored.sha256.text, TrustBasis.UNVERIFIED
    )
    assert plan_trust([held(stored)], [stored], controller_says(stored)) == AlreadyStored(
        stored.sha256.text, TrustBasis.CONTROLLER
    )


def test_rule_5_nothing_stored_stores_the_chosen_key() -> None:
    new = cand(3)
    assert plan_trust([], [cand(9), new], controller_says(new)) == StoreNew(new, TrustBasis.CONTROLLER)
    assert plan_trust([], [new], NO_EXPECTATION) == StoreNew(new, TrustBasis.UNVERIFIED)


def test_rule_5_an_ambiguous_first_use_choice_is_refused() -> None:
    assert isinstance(plan_trust([], [cand(1), cand(2)], NO_EXPECTATION), Refused)


@pytest.mark.security("T8")
def test_rule_6_a_stored_key_that_is_not_offered_is_replaced_by_the_chosen_one() -> None:
    old, new = cand(1), cand(2)
    assert plan_trust([held(old)], [new], controller_says(new)) == Replace(held(old), new, TrustBasis.CONTROLLER)
    assert plan_trust([held(old)], [new], NO_EXPECTATION) == Replace(held(old), new, TrustBasis.UNVERIFIED)


def test_rule_6_a_stored_key_still_offered_but_not_the_one_the_controller_names_is_replaced() -> None:
    stored, named = cand(1, ED), cand(2, ECDSA)
    decision = plan_trust([held(stored)], [stored, named], controller_says(named))
    assert decision == Replace(held(stored), named, TrustBasis.CONTROLLER)
    # The next run converges: the stored key is the one the controller names.
    assert isinstance(plan_trust([held(named)], [stored, named], controller_says(named)), AlreadyStored)


# --- apply_decision: policy x answer ---------------------------------------------------------------------------


def subject() -> TrustSubject:
    return TrustSubject(
        site_id="default", name="AP-1", alias=ALIAS, address=ip_address("192.168.1.2"), port=22,
        allow_public_address=False, config_pin=None, controller_fingerprint=None,
    )  # fmt: skip


def run_policy(
    decision: TrustDecision,
    store: Memory,
    *,
    yes: bool = False,
    unverified: bool = False,
    answer: bool = False,
) -> tuple[TrustOutcome, list[Prompt]]:
    asked: list[Prompt] = []

    def confirm(prompt: Prompt) -> bool:
        asked.append(prompt)
        return answer

    policy = TrustPolicy(assume_yes=yes, accept_unverified=unverified, confirm=confirm)
    return apply_decision(subject(), decision, store, policy).outcome, asked


NEW, OLD = cand(2), cand(1)


@pytest.mark.parametrize(
    ("decision", "yes", "unverified", "answer", "outcome", "asks"),
    [
        (StoreNew(NEW, TrustBasis.CONTROLLER), True, False, False, TrustOutcome.STORED, False),
        (StoreNew(NEW, TrustBasis.CONTROLLER), False, False, True, TrustOutcome.STORED, True),
        (StoreNew(NEW, TrustBasis.CONTROLLER), False, False, False, TrustOutcome.DECLINED, True),
        (StoreNew(NEW, TrustBasis.CONTROLLER), False, True, False, TrustOutcome.DECLINED, True),
        (StoreNew(NEW, TrustBasis.UNVERIFIED), True, False, False, TrustOutcome.DECLINED, True),
        (StoreNew(NEW, TrustBasis.UNVERIFIED), False, True, False, TrustOutcome.STORED, False),
        (StoreNew(NEW, TrustBasis.UNVERIFIED), False, False, True, TrustOutcome.STORED, True),
    ],
)
def test_a_new_key_follows_the_policy(
    decision: TrustDecision, yes: bool, unverified: bool, answer: bool, outcome: TrustOutcome, asks: bool
) -> None:
    store = Memory()
    result, asked = run_policy(decision, store, yes=yes, unverified=unverified, answer=answer)
    assert result is outcome and bool(asked) is asks
    assert store.rows == ([NEW.entry(ALIAS)] if outcome is TrustOutcome.STORED else [])
    assert all(p.kind is PromptKind.NEW for p in asked)


@pytest.mark.security("T8")
@pytest.mark.parametrize(
    ("basis", "yes", "unverified", "answer", "outcome", "asks"),
    [
        (TrustBasis.CONTROLLER, True, False, False, TrustOutcome.REPLACED, False),
        (TrustBasis.CONFIG_PIN, True, False, False, TrustOutcome.REPLACED, False),
        (TrustBasis.CONTROLLER, False, False, True, TrustOutcome.REPLACED, True),
        (TrustBasis.CONTROLLER, False, False, False, TrustOutcome.DECLINED, True),
        (TrustBasis.CONTROLLER, False, True, False, TrustOutcome.DECLINED, True),
        (TrustBasis.UNVERIFIED, True, True, False, TrustOutcome.DECLINED, True),
        (TrustBasis.UNVERIFIED, False, False, True, TrustOutcome.REPLACED, True),
    ],
)
def test_a_replace_is_silent_only_for_a_verified_key_under_yes(
    basis: TrustBasis, yes: bool, unverified: bool, answer: bool, outcome: TrustOutcome, asks: bool
) -> None:
    store = Memory([OLD.entry(ALIAS)])
    result, asked = run_policy(
        Replace(OLD.entry(ALIAS), NEW, basis), store, yes=yes, unverified=unverified, answer=answer
    )
    assert result is outcome and bool(asked) is asks
    expected = NEW if outcome is TrustOutcome.REPLACED else OLD
    assert store.rows == [expected.entry(ALIAS)]
    assert all(p.kind is PromptKind.REPLACE and p.new_fingerprint == NEW.sha256.text for p in asked)
    if asked:
        assert (
            OLD.sha256.text in asked[0].text and NEW.sha256.text in asked[0].text and "default: AP-1" in asked[0].text
        )


def test_a_replace_reports_old_and_new_fingerprint_and_a_refusal_is_a_failure() -> None:
    store = Memory([OLD.entry(ALIAS)])
    result = apply_decision(
        subject(), Replace(OLD.entry(ALIAS), NEW, TrustBasis.CONTROLLER), store,
        TrustPolicy(assume_yes=True, accept_unverified=False, confirm=lambda p: False),
    )  # fmt: skip
    assert result.detail == f"{OLD.sha256.text} -> {NEW.sha256.text}"
    refused = apply_decision(
        subject(), Refused("nope", TrustBasis.CONTROLLER), store,
        TrustPolicy(assume_yes=True, accept_unverified=True, confirm=lambda p: True),
    )  # fmt: skip
    assert refused.outcome is TrustOutcome.FAILED and refused.detail == "nope"


def test_a_store_that_refuses_the_write_is_a_failure_not_a_crash() -> None:
    class Stale(Memory):
        def replace(self, entry: KnownHostEntry, expected_old: KnownHostEntry) -> None:
            raise HostKeyTrustError("the stored key changed since it was shown")

    result = apply_decision(
        subject(), Replace(OLD.entry(ALIAS), NEW, TrustBasis.CONTROLLER), Stale([OLD.entry(ALIAS)]),
        TrustPolicy(assume_yes=True, accept_unverified=False, confirm=lambda p: False),
    )  # fmt: skip
    assert result.outcome is TrustOutcome.FAILED and "changed since it was shown" in result.detail


# --- inspect_access_point: the keyscan fast path ---------------------------------------------------------------


class Scans:
    def __init__(self, quick: Sequence[HostKeyCandidate], full: Sequence[HostKeyCandidate]) -> None:
        self.quick, self.full = quick, full
        self.calls: list[str | None] = []

    def __call__(self, address: object, port: int, key_type: str | None) -> Sequence[HostKeyCandidate]:
        self.calls.append(key_type)
        return self.full if key_type is None else self.quick


def test_a_stored_trusted_key_is_checked_with_one_connection_for_its_own_type() -> None:
    stored = cand(1)
    scan = Scans([stored], [])
    decision = inspect_access_point(subject(), Memory([held(stored)]), scan)
    assert decision == AlreadyStored(stored.sha256.text, TrustBasis.UNVERIFIED) and scan.calls == [ED]


@pytest.mark.parametrize("quick", [[], [cand(2)]])
def test_an_empty_or_different_quick_answer_falls_back_to_the_full_scan(quick: list[HostKeyCandidate]) -> None:
    stored, other = cand(1), cand(2)
    scan = Scans(quick, [other])
    decision = inspect_access_point(subject(), Memory([held(stored)]), scan)
    assert decision == Replace(held(stored), other, TrustBasis.UNVERIFIED) and scan.calls == [ED, None]


def test_a_stored_key_that_does_not_satisfy_the_expectation_skips_the_quick_check() -> None:
    stored, named = cand(1), cand(2)
    scan = Scans([stored], [stored, named])
    trusted = dataclasses.replace(subject(), controller_fingerprint=named.sha256.text)
    decision = inspect_access_point(trusted, Memory([held(stored)]), scan)
    assert isinstance(decision, Replace) and scan.calls == [None]


def test_the_address_is_checked_before_any_connection() -> None:
    public = dataclasses.replace(subject(), address=ip_address("8.8.8.8"))
    scan = Scans([cand(1)], [cand(1)])
    decision = inspect_access_point(public, Memory(), scan)
    assert isinstance(decision, Refused) and "not a private network address" in decision.reason and scan.calls == []


def test_a_timeout_of_the_quick_check_is_a_refusal_not_a_fallback() -> None:
    calls: list[str | None] = []

    def scan(address: object, port: int, key_type: str | None) -> Sequence[HostKeyCandidate]:
        calls.append(key_type)
        raise HostKeyTrustError("ssh-keyscan did not finish within 30 s")

    decision = inspect_access_point(subject(), Memory([held(cand(1))]), scan)
    assert isinstance(decision, Refused) and calls == [ED]


# --- check_host_keys: what a scanning run reports -------------------------------------------------------------


def test_the_run_gate_reports_every_result_except_already_stored() -> None:
    stored, fresh = cand(1), cand(2)
    store = Memory([held(stored)])
    reported: list[str] = []
    answers: list[Prompt] = []

    def confirm(prompt: Prompt) -> bool:
        answers.append(prompt)
        return True

    second = dataclasses.replace(subject(), name="AP-2", alias="uwo-" + "1" * 32)

    def scan(address: object, port: int, key_type: str | None) -> Sequence[HostKeyCandidate]:
        return [stored] if key_type == ED else [fresh]

    check_host_keys(
        [subject(), second], store, TrustPolicy(assume_yes=False, accept_unverified=False, confirm=confirm),
        lambda result: reported.append(f"{result.ap_name}:{result.outcome}"), scan,
    )  # fmt: skip
    assert reported == ["AP-2:stored"] and len(answers) == 1 and answers[0].kind is PromptKind.NEW


def test_a_decline_in_the_run_gate_changes_nothing() -> None:
    store = Memory()
    reported: list[str] = []
    check_host_keys(
        [subject()], store, TrustPolicy(assume_yes=False, accept_unverified=False, confirm=lambda p: False),
        lambda result: reported.append(str(result.outcome)), Scans([], [cand(1)]),
    )  # fmt: skip
    assert reported == ["declined"] and store.rows == [] and store.writes == []
