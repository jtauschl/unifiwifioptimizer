"""Static review of the release workflow, as a gate.

The jobs that attest, publish and release run only on a real tag, so nothing can execute them before the
release. What can be checked now is the structure that makes them safe: which job may hold which
permission, which job may read the repository, what each job waits for, that every action is pinned to a
commit, and that no publish step can skip a file silently. The release checklist's review items are these
assertions, so a later edit to the workflow cannot drop one unnoticed.
"""

import re
from pathlib import Path
from typing import Any

import pytest
import yaml

# YAML 1.1 reads the workflow trigger key `on` as the boolean True, so keys are not only strings.
Document = dict[Any, Any]

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github" / "workflows"
RELEASE_PATH = WORKFLOWS / "release.yml"

NEEDS = {
    "test": set(),
    "build": {"test"},
    "sbom": {"build"},
    "attest": {"build"},
    "preflight": {"build"},
    "publish": {"build", "attest", "sbom", "preflight"},
    "pypi-verify": {"build", "publish"},
    "github-release": {"build", "sbom", "publish", "pypi-verify"},
}
CHECKOUT_JOBS = {"test", "build", "sbom"}
TAG_ONLY_JOBS = {"attest", "preflight", "publish", "pypi-verify", "github-release"}
PRIVILEGES = {
    "attest": {"contents": "read", "id-token": "write", "attestations": "write"},
    "publish": {"id-token": "write"},
    "github-release": {"contents": "write"},
}
TAG_GUARD = "github.ref_type == 'tag'"
CONDITIONS = {
    "pypi-verify": (
        "${{ !cancelled() && github.ref_type == 'tag' && needs.build.result == 'success' "
        "&& needs.publish.result != 'skipped' }}"
    ),
    "github-release": (
        "${{ !cancelled() && github.ref_type == 'tag' && needs.build.result == 'success' "
        "&& needs.sbom.result == 'success' && needs.pypi-verify.result == 'success' }}"
    ),
}
EXPECTED_PATHS = [
    ".github/workflows/release.yml",
    ".github/actions/**",
    "scripts/release_guard.py",
    "scripts/dist_check.py",
    "scripts/sbom_set_root_version.py",
    "pyproject.toml",
    "build-constraints.txt",
    "dev",
    "CHANGELOG.md",
]
PINNED = re.compile(r"^\s*(?:- )?uses: (?P<action>[\w./-]+)@(?P<sha>[0-9a-f]{40}) # v\d[\w.]*\s*$")


def load(path: Path) -> Document:
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(document, dict)
    return document


@pytest.fixture(scope="module")
def release() -> Document:
    return load(RELEASE_PATH)


def steps_of(job: Document) -> list[Document]:
    steps: list[Document] = job["steps"]
    return steps


def run_text(job: Document) -> str:
    return "\n".join(str(step.get("run", "")) for step in steps_of(job))


def uses_steps(document: Document) -> list[tuple[str, Document]]:
    if "jobs" in document:
        steps = [step for job in document["jobs"].values() for step in steps_of(job)]
    else:
        steps = document["runs"]["steps"]
    return [(str(step["uses"]), step) for step in steps if "uses" in step]


def local_actions(release: Document) -> list[Path]:
    paths = {
        ROOT / action.removeprefix("./") / "action.yml" for action, _ in uses_steps(release) if action.startswith("./")
    }
    return sorted(paths)


def test_the_jobs_are_exactly_the_planned_chain(release: Document) -> None:
    assert set(release["jobs"]) == set(NEEDS)


def test_every_job_waits_for_exactly_the_jobs_whose_outputs_or_success_it_depends_on(release: Document) -> None:
    for name, expected in NEEDS.items():
        assert set(release["jobs"][name].get("needs", [])) == expected, name


def test_the_workflow_runs_on_tags_and_dry_runs_on_release_branches(release: Document) -> None:
    trigger = release[True]
    assert trigger["push"]["tags"] == ["v*"] and trigger["push"]["branches"] == ["release/**"]
    assert trigger["push"]["paths"] == EXPECTED_PATHS
    assert "workflow_dispatch" in trigger


def test_only_the_publishing_jobs_are_confined_to_tags(release: Document) -> None:
    for name, job in release["jobs"].items():
        guard = str(job.get("if", ""))
        assert (TAG_GUARD in guard) == (name in TAG_ONLY_JOBS), name


def test_the_late_jobs_keep_running_after_a_failed_publish_and_name_their_conditions(release: Document) -> None:
    for name, expected in CONDITIONS.items():
        assert release["jobs"][name]["if"] == expected, name
    for name in TAG_ONLY_JOBS - set(CONDITIONS):
        assert release["jobs"][name]["if"] == TAG_GUARD, name


def test_the_workflow_default_is_read_only_and_privileges_sit_on_single_jobs(release: Document) -> None:
    assert release["permissions"] == {"contents": "read"}
    for name, job in release["jobs"].items():
        assert job.get("permissions") == PRIVILEGES.get(name), name


def test_runs_of_one_ref_never_cancel_each_other(release: Document) -> None:
    assert release["concurrency"] == {
        "group": "${{ github.workflow }}-${{ github.ref }}",
        "cancel-in-progress": False,
    }


def test_every_job_has_a_timeout(release: Document) -> None:
    for name, job in release["jobs"].items():
        assert isinstance(job.get("timeout-minutes"), int), name


def test_only_the_gate_build_and_sbom_jobs_read_the_repository(release: Document) -> None:
    for name, job in release["jobs"].items():
        checks_out = any(action.startswith("actions/checkout@") for action, _ in uses_steps({"jobs": {name: job}}))
        assert checks_out == (name in CHECKOUT_JOBS), name


def test_no_checkout_keeps_the_token_and_the_history_reaches_the_version_derivation(release: Document) -> None:
    for action, step in uses_steps(release):
        if action.startswith("actions/checkout@"):
            assert step["with"]["persist-credentials"] is False
            assert step["with"]["fetch-depth"] == 0


def test_every_action_is_pinned_to_a_commit_with_a_version_comment() -> None:
    lines = [
        line
        for path in [RELEASE_PATH, *local_actions(load(RELEASE_PATH))]
        for line in path.read_text(encoding="utf-8").splitlines()
        if re.match(r"^\s*(- )?uses: ", line) and not re.match(r"^\s*(- )?uses: \./", line)
    ]
    assert lines
    for line in lines:
        assert PINNED.match(line), line


def test_local_actions_are_resolved_and_hold_to_the_same_rules(release: Document) -> None:
    paths = local_actions(release)
    assert [p.relative_to(ROOT).as_posix() for p in paths] == [".github/actions/toolchain/action.yml"]
    for path in paths:
        for action, step in uses_steps(load(path)):
            assert action.startswith("astral-sh/setup-uv@")
            assert step["with"]["enable-cache"] is False


def test_no_uv_setup_uses_a_cache(release: Document) -> None:
    uv_steps = [step for action, step in uses_steps(release) if action.startswith("astral-sh/setup-uv@")]
    assert uv_steps
    for step in uv_steps:
        assert step["with"]["enable-cache"] is False
        assert step["with"]["version"] == "${{ env.UV_VERSION }}"


def test_the_uv_version_is_one_value_across_workflows_and_the_dev_wrapper(release: Document) -> None:
    versions = {
        path.name: str(load(path)["env"]["UV_VERSION"])
        for path in (RELEASE_PATH, WORKFLOWS / "ci.yml", WORKFLOWS / "security.yml")
    }
    match = re.search(r"^UV_VERSION=(\S+)$", (ROOT / "dev").read_text(encoding="utf-8"), re.MULTILINE)
    assert match is not None
    versions["dev"] = match.group(1)
    assert len(set(versions.values())) == 1, versions


def test_the_pull_request_gate_installs_its_tools_through_the_shared_action() -> None:
    ci = load(WORKFLOWS / "ci.yml")
    gate_steps = ci["jobs"]["local-gate"]["steps"]
    assert any(step.get("uses") == "./.github/actions/toolchain" for step in gate_steps)
    assert "gitleaks.tar.gz" not in run_text(ci["jobs"]["local-gate"])


def downloads(job: Document) -> list[tuple[int, str]]:
    return [
        (index, str(step["with"]["path"]))
        for index, step in enumerate(steps_of(job))
        if str(step.get("uses", "")).startswith("actions/download-artifact@")
    ]


TOOLS_CHECK = 'echo "$TOOLS_SHA256  tools/release_guard.py" | sha256sum -c -'


def verifies(step: Document, path: str) -> bool:
    text = str(step.get("run", ""))
    return TOOLS_CHECK in text if path == "tools" else f"verify-dir --dir {path} " in text


def test_the_step_right_after_the_last_download_verifies_every_downloaded_artifact(release: Document) -> None:
    for name, job in release["jobs"].items():
        found = downloads(job)
        if not found:
            continue
        steps = steps_of(job)
        verify = steps[found[-1][0] + 1]
        assert [index for index, _ in found] == list(range(found[0][0], found[-1][0] + 1)), name
        for _, path in found:
            assert verifies(verify, path), f"{name}: {path} is not verified right after the downloads"


def test_no_run_block_can_swallow_a_failure(release: Document) -> None:
    for name, job in release["jobs"].items():
        text = run_text(job)
        assert "|| true" not in text and "|| :" not in text, name


def test_the_toolchain_action_downloads_into_the_runner_temp_directory_not_the_workspace() -> None:
    composite = load(ROOT / ".github" / "actions" / "toolchain" / "action.yml")
    text = run_text(composite["runs"])
    assert 'curl -sSL -o "$RUNNER_TEMP/' in text and 'cd "$RUNNER_TEMP"' in text
    assert not re.search(r"curl[^\n]* -o (?!\"\$RUNNER_TEMP/)", text)


def test_artifact_directories_are_checked_for_exact_membership_not_just_for_intact_files(release: Document) -> None:
    for name in ("sbom", "attest", "publish"):
        assert "verify-dir --dir dist " in run_text(release["jobs"][name]), name
    text = run_text(release["jobs"]["github-release"])
    for directory in ("dist", "sbom", "notes"):
        assert f"verify-dir --dir {directory} " in text, directory


def test_no_run_block_interpolates_an_expression(release: Document) -> None:
    documents = [release, load(ROOT / ".github" / "actions" / "toolchain" / "action.yml")]
    for document in documents:
        jobs = document["jobs"].values() if "jobs" in document else [document["runs"]]
        for job in jobs:
            assert "${{" not in run_text(job)


def test_the_composite_action_installs_the_version_it_is_given_and_callers_pass_the_single_source(
    release: Document,
) -> None:
    composite = load(ROOT / ".github" / "actions" / "toolchain" / "action.yml")
    (uv,) = [step for action, step in uses_steps(composite) if action.startswith("astral-sh/setup-uv@")]
    assert uv["with"]["version"] == "${{ inputs.uv-version }}"
    callers = [release["jobs"]["test"]["steps"], load(WORKFLOWS / "ci.yml")["jobs"]["local-gate"]["steps"]]
    for steps in callers:
        (call,) = [step for step in steps if step.get("uses") == "./.github/actions/toolchain"]
        assert call["with"] == {"uv-version": "${{ env.UV_VERSION }}"}


def test_the_gate_must_leave_the_tree_clean_before_the_build_is_compared(release: Document) -> None:
    steps = steps_of(release["jobs"]["test"])
    gate = next(i for i, step in enumerate(steps) if step.get("run") == "./dev ci")
    clean = next(
        i
        for i, step in enumerate(steps)
        if re.search(
            r'if \[\[ -n "\$\(git status --porcelain\)" \]\]; then.*exit 1', str(step.get("run", "")), re.DOTALL
        )
    )
    hashes = next(i for i, step in enumerate(steps) if step.get("id") == "hashes")
    assert gate < clean < hashes


def test_the_notes_are_checked_on_release_branches_too_so_the_dry_run_exercises_them(release: Document) -> None:
    notes = next(step for step in steps_of(release["jobs"]["build"]) if step.get("id") == "notes")
    assert "if" not in notes and "release/*" in notes["run"]


def test_the_attestation_and_the_upload_are_actually_there(release: Document) -> None:
    attest_uses = [action for action, _ in uses_steps({"jobs": {"attest": release["jobs"]["attest"]}})]
    publish_uses = [action for action, _ in uses_steps({"jobs": {"publish": release["jobs"]["publish"]}})]
    assert any(action.startswith("actions/attest-build-provenance@") for action in attest_uses)
    assert any(action.startswith("pypa/gh-action-pypi-publish@") for action in publish_uses)


def test_the_published_release_is_read_back_and_must_be_published_and_complete(release: Document) -> None:
    last = steps_of(release["jobs"]["github-release"])[-1]
    assert "release=published" in last["run"] and "state=complete" in last["run"]


def test_the_draft_is_filled_and_checked_before_it_is_published(release: Document) -> None:
    text = run_text(release["jobs"]["github-release"])
    create, check, publish = (text.index(marker) for marker in ("--draft", "state=complete", "--draft=false"))
    assert create < check < publish


def test_privileged_jobs_never_talk_to_origin_without_a_checkout(release: Document) -> None:
    for name in TAG_ONLY_JOBS:
        assert not re.search(r"\borigin\b", run_text(release["jobs"][name])), name
    assert release["jobs"]["github-release"]["env"]["GH_REPO"] == "${{ github.repository }}"


def test_the_github_release_is_verified_against_the_tag_and_never_generates_notes(release: Document) -> None:
    text = run_text(release["jobs"]["github-release"])
    assert re.search(r"gh release create[^\n]*--verify-tag", text), "the tag must exist before the draft is created"
    assert re.search(r"gh release edit[^\n]*--verify-tag", text), "the tag must still exist when the draft is published"
    assert re.search(r"gh release edit[^\n]*--notes-file notes/notes.md", text), (
        "a leftover draft keeps no foreign notes"
    )
    assert "ls-remote" in text and "--generate-notes" not in text


def test_pypi_upload_has_no_skip_existing_and_only_uploads_the_selected_files(release: Document) -> None:
    assert "skip-existing" not in RELEASE_PATH.read_text(encoding="utf-8")
    publish = release["jobs"]["publish"]
    assert publish["environment"] == "pypi"
    (upload,) = [
        step for step in steps_of(publish) if str(step.get("uses", "")).startswith("pypa/gh-action-pypi-publish@")
    ]
    assert upload["with"] == {"packages-dir": "upload"}
    assert upload["if"] == "steps.select.outputs.count != '0'"


def test_the_workflow_uses_no_stored_secret(release: Document) -> None:
    assert "secrets." not in RELEASE_PATH.read_text(encoding="utf-8")


SEMVER_JOBS = ("test", "build", "sbom", "attest", "publish", "github-release")
SEMVER_PREDICATE = "=~ ^v(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)$"


def test_every_job_that_builds_attests_publishes_or_releases_checks_the_tag_itself_first(release: Document) -> None:
    """Each such job re-validates the tag before its first step acts, unconditionally: a step condition could
    skip it, and a `continue-on-error` would let the job go on after it failed."""
    for name in SEMVER_JOBS:
        first = steps_of(release["jobs"][name])[0]
        assert "if" not in first and "continue-on-error" not in first, name
        assert SEMVER_PREDICATE in first["run"] and "GITHUB_REF_TYPE" in first["run"], name
