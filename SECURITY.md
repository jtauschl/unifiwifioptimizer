# Security Policy

## Supported versions

Only the latest tagged release is supported. Fixes ship as part of the next
tagged release rather than as a backport to an older one.

## Reporting a vulnerability

Report a suspected vulnerability privately through GitHub's private vulnerability reporting:
[Report a vulnerability](https://github.com/jtauschl/unifiwifioptimizer/security/advisories/new).
If you cannot use that form, email **security@tauschl.de** instead.

**Do not open a public GitHub issue for a suspected vulnerability.**

Include in your report:
- The affected file, function, or command-line flag.
- The release tag or commit you found it against.
- The impact — what a UniFi operator running this tool would actually get wrong or exposed to.
- Steps to reproduce, or reasoning if reproduction requires specific hardware/firmware.

Expect an acknowledgment within 5 business days.

## Scope and threat model

`unifiwifioptimizer` is a read-only diagnostic tool. It:

- Reads UniFi Network API configuration and neighbor scan data.
- Runs `ssh` and `iw scan` on managed access points to collect neighbor RSSI.
- **Never writes back** to the UniFi controller or the APs. All recommendations are applied manually.

Security-relevant surfaces:

- **Configuration file (`config.yaml`)** contains a UniFi Network API key and, optionally, SSH credentials. The file is gitignored and must never be committed.
- **TLS certificate verification is disabled** (`curl -k`) for calls to the UniFi controller, and **SSH host-key verification is disabled** (`StrictHostKeyChecking=no`) for the AP neighbor scan — see `README.md#security-notes` for the rationale. Both are deliberate, accepted tradeoffs for a tool targeting a trusted local network, not oversights; this tool's transport security should not be relied on across an untrusted network boundary.
- **No telemetry, no outbound calls** beyond the configured UniFi controller and the configured APs.

Bugs that could invalidate any of the above (accidental write, credential leak in logs, a controller URL or AP host derived from untrusted/remote input rather than local `config.yaml`, unintended outbound requests) are in scope.
