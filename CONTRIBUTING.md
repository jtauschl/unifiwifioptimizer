# Contributing

Bug reports and feature requests are welcome via [GitHub Issues](https://github.com/jtauschl/unifiwifioptimizer/issues) — use the bug/feature templates, they ask for the details (UniFi Network Application version, AP model/firmware) needed to reproduce or evaluate most requests. Questions belong in [GitHub Discussions](https://github.com/jtauschl/unifiwifioptimizer/discussions).

## Setting up

```bash
git clone https://github.com/jtauschl/unifiwifioptimizer.git
cd unifiwifioptimizer
./dev bootstrap
```

## Pull requests

1. Fork the repo and branch off the currently open release branch (`release/0.5.0`) — `main` only ever receives finished releases.
2. Keep changes focused — one logical change per PR.
3. Run `./dev ci` (this repo's full local gate — its own build/lint/test gates, not the maintainer's separate internal conformance tooling) and confirm it passes before opening the PR; CI additionally runs its required checks, plus any extra cheap checks the project enables, on every push and pull request.
4. Test against a real UniFi controller where the change touches API calls, SSH scanning, or the RF corridor math — the automated tests cover the model and the parsers, not your controller's firmware.
5. Update `docs/PROFILES.md`/`docs/ALGORITHM.md` if the change affects profile fields or the RF model.
6. Open the PR using the provided template — fill in Summary, Risk, and Release notes.

## Code style

- POSIX-compatible Bash where possible, shellcheck- and shfmt-clean (`./dev lint`, `./dev format`).
- `UPPER_CASE` for constants, `lower_case` for local variables.
- Embedded Ruby/Python is for YAML parsing and JSON extraction only — no logic there.
- No external package dependencies — only standard system tools (`bash`, `curl`, `python3`, `ruby`, `ssh`, `awk`).
- The tool never writes to the UniFi controller — read-only stays read-only.

## What won't be merged

- Anything that adds write access to the UniFi controller.
- New external dependencies beyond the standard system tools listed above.
