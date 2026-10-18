# Contributing

Bug reports and feature requests are welcome via [GitHub Issues](https://github.com/jtauschl/unifiwifioptimizer/issues) — use the bug/feature templates, they ask for the details (UniFi Network Application version, AP model/firmware) needed to reproduce or evaluate most requests. Questions belong in [GitHub Discussions](https://github.com/jtauschl/unifiwifioptimizer/discussions).

## Setting up

```bash
git clone https://github.com/jtauschl/unifiwifioptimizer.git
cd unifiwifioptimizer
./dev bootstrap   # checks the toolchain (uv, OpenSSH >= 8.4, shellcheck, shfmt, actionlint, gitleaks, docker) and syncs the locked environment
```

`./dev help` lists every check as its own subcommand. Run the tool from the checkout with `uv run unifiwifioptimizer …`. Without `uv`, `python3 -m venv .venv && .venv/bin/pip install -e '.[dev]'` gives an equivalent environment for the Python checks (Python 3.11 or newer); the pinned versions are the same in `[project.optional-dependencies]` and `[dependency-groups]`.

## Pull requests

1. Fork the repo and branch off the currently open release branch (see the branches on GitHub; `release/X.Y.Z`) — `main` only ever receives finished releases.
2. Keep changes focused — one logical change per PR.
3. Run `./dev ci` (this repo's full local gate — its own build/lint/test gates, not the maintainer's separate internal conformance tooling) and confirm it passes before opening the PR; CI additionally runs its required checks, plus any extra cheap checks the project enables, on every push and pull request.
4. Test against a real UniFi controller where the change touches API calls, SSH scanning, or the RF corridor math — the automated tests cover the model and the parsers, not your controller's firmware.
5. Update `docs/PROFILES.md`/`docs/ALGORITHM.md` if the change affects profile fields or the RF model.
6. Open the PR using the provided template — fill in Summary, Risk, and Release notes.

## Code style

- Python: `ruff` (lint + format, 120 columns), `mypy --strict`, `bandit`; configuration lives in `pyproject.toml` only. Comments explain why, never what.
- Architecture: `domain/`, `rf/`, `compliance/`, `analysis/` and `ports/` are pure — no I/O modules and nothing from `adapters/`, `app/`, `cli/`, `report/` or `config/`. `subprocess` only in `adapters/ssh/`, never with `shell=True`; controller JSON is parsed in `adapters/unifi/client.py` only; certificate verification is disabled only inside the pinned connection. `tests/unit/test_architecture.py` checks these rules on the AST with import aliases resolved and keeps a table of known-bad snippets; ruff's `S` rules cover the rest.
- Tests: `tests/unit/` needs no network and writes nothing (the structural tests read the repo's own files); `tests/integration/` is marked `integration` and runs against the Docker harness in `docker/`. Coverage has two tiers: the hard floor on the unit tier is `./dev coverage`'s `--cov-fail-under`; the soft per-layer targets and their measurement over unit plus integration are `tests/tools/coverage_layers.py` (`./dev coverage-layers`), which lists every file under its layer's target. Security-relevant tests carry `@pytest.mark.security("Tn")`; `tests/unit/test_security_inventory.py` keeps the topic list and runs the inventory both ways, and `tests/conftest.py` checks at collection time that pytest's markers match what the inventory read, so write the marker plainly on the test; the subset runs as `pytest -m "security and not integration"`.
- Test data: the golden report files in `tests/fixtures/golden/` change only on purpose; regenerate them with `uv run python -m tests.tools.regenerate_golden` and review the diff like code. Controller fixtures are anonymised projections (`tests/fixtures/README.md`); never commit a live dump, and produce a fixture only through `tests/tools/anonymize_fixtures.py`.
- Dependencies: `pyyaml` is the only runtime dependency, and that stays so. Dev tools are pinned exactly; `uv.lock` and the hashed `build-constraints.txt` are committed and checked by `./dev lock-check`.
- Shell (`dev`, the access-point scan script and the harness stubs): shellcheck- and shfmt-clean (`./dev shellcheck`, `./dev format`). The scan script runs on the access point under busybox `ash`, not bash, and carries `# shellcheck shell=sh`.
- The tool never writes to the UniFi controller — read-only stays read-only.

## What won't be merged

- Anything that adds write access to the UniFi controller.
- A new runtime dependency, or a TLS/host-key verification bypass.
