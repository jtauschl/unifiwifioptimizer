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

## What the tool does

`unifiwifioptimizer` is a read-only diagnostic tool. It:

- Reads configuration, device and (optionally) client data from the UniFi Network API with `GET` requests only.
- Runs `ssh` to the managed access points and executes one scan script there to collect neighbour RSSI.
- **Never writes** to the UniFi controller. The one change it can make on an access point is bringing a scan
  interface up and down around a scan, and only when you set `scan_interface_toggle: true` for that site; the
  script puts back the interface state it found.
- Makes no other outbound connection than to the configured controller and the configured access points. There is
  no telemetry.

All recommendations are applied by you, by hand, in the UniFi Network Application.

## Assets and adversaries

| Asset | Where it lives |
| --- | --- |
| Controller API key | `controller.api_key` in the configuration file, or the `UNIFI_API_KEY` environment variable |
| Access-point SSH credentials | the controller (`ssh.auth: controller`), your SSH key or agent (`key`), or `ssh.password` / `UNIFI_SSH_PASSWORD` (`password`) |
| Access-point host keys | the tool's own `known_hosts` under `$XDG_STATE_HOME/unifiwifioptimizer/` |
| Network inventory | access-point names and MACs, WLAN names, neighbour RSSI in the report; client signal counts, never client identities |

The tool defends against:

- **A machine on the LAN that impersonates the controller or an access point** (TLS and SSH host-key checks, below).
- **A controller or access point that returns hostile data**: crafted JSON, oversized or deeply nested answers, escape
  sequences in SSIDs or device names, an access point address outside your network.
- **Another local user on the same host** reading your credentials or replacing the files the tool trusts.
- **A tampered release**: see Release verification.

It does not defend against an attacker who already runs code as your user or as root on the machine that runs the
tool, and not against a compromised controller whose *genuine* credentials you chose to trust.

## Trust boundaries and controls

### Controller connection (TLS)

TLS verification is on in every mode and cannot be switched off. Exactly one of three modes applies:

1. **System roots** (no `ca_cert`, no `cert_fingerprint`): the certificate must chain to a public root and match the host.
2. **Private CA** (`controller.ca_cert`): the certificate must chain to your CA file and match the host.
3. **Certificate pin** (`controller.cert_fingerprint`): the SHA-256 of the presented certificate must equal the pin, and
   the check runs before the first request byte is sent. Use this for the controller's factory self-signed certificate.

A controller with a self-signed certificate fails with exit code 4 until you pin it. `controller-fingerprint` prints
what the controller presents right now; that is trust on first use, so compare it with the certificate view in the
controller before you copy it into the configuration.

Requests are `GET` only. Redirects are refused. Response bodies are capped at 64 MiB and compressed responses are
refused, so the cap cannot be bypassed. Every call has a timeout.

### Access-point connection (SSH)

- The `ssh` binary of your system is run as a subprocess with an argument list, never through a shell. OpenSSH 8.4 or
  newer is required.
- Host keys are verified against the tool's own `known_hosts` (`StrictHostKeyChecking=yes`, no system-wide file, no key
  updates). The key of each access point is stored under an alias derived from the controller, the site and the
  access point's MAC.
- **A scan never adds a host key.** An access point without a stored key is reported and skipped before any connection.
- Keys are stored only by `trust-host-keys`, on one of three bases, in this order: a pin you configured
  (`ssh.host_keys`), the fingerprint the controller itself reports for that access point, or — when neither exists —
  trust on first use, which needs your confirmation per access point or `--accept-unverified`. `--yes` confirms
  verified matches only. If a configured pin and the controller's fingerprint both exist and differ, that access
  point is refused.
- Access-point addresses must be private addresses unless you set `allow_public_ap_addresses: true` for the site.

### What runs on the access point

One scan script runs through `sh -s` with its arguments on standard input. It writes no file on the access point and
keeps no state outside its shell variables; a helper process it may start to bound one scan ends with that scan. It calls
`iw scan`; with `scan_interface_toggle: true` it additionally brings a scan interface that is down up before the scan
and puts it down again afterwards, also when the script is ended by a hang-up, interrupt, termination or broken-pipe signal; a kill or a power loss leaves the interface up. Without the toggle, an interface that is down is
reported as `interface_down` and left alone.

### Credentials and secrets

- The configuration file must be a regular file you own, accessible to nobody else (mode `0600` or stricter), in a
  directory that is not writable by group or others. A symbolic link in place of the file or of its directory is
  refused. Anything else is an error; the tool does not warn and continue. `init` creates the file with mode `0600`.
- `UNIFI_API_KEY` and `UNIFI_SSH_PASSWORD` are removed from the tool's environment as soon as they are read, so child
  processes never inherit them.
- The SSH password reaches OpenSSH only through `SSH_ASKPASS` in a minimal, allow-listed environment of the child
  process. It is never in an argument list, a log line, an exception message or a temporary file. With
  `ssh.auth: controller` the tool reads the controller-managed SSH credentials through the API key, which therefore
  must belong to an account with the full Administrator role.
- Secrets are wrapped in a type that renders as `***`, and a report refuses to serialise one.
- `--dump-api DIR` writes, per endpoint, the typed models the tool read with secret-looking keys masked at every
  depth. Fields the tool does not use are never written; the dump only counts them. `DIR` must be owned by you and
  closed to others (mode `0700`), or the command stops.

### Untrusted input

Controller answers, `iw` output and SSH error output are untrusted. Controller JSON is parsed in exactly one place, with
limits on size, nesting, item counts and value ranges; a record that cannot be understood is reported as unparsable
instead of guessed. Every string that comes from the network reaches your terminal through a sanitiser that replaces
control and escape characters, so an SSID cannot rewrite your screen.

### Memory hygiene

Python cannot reliably erase a string from memory. The tool keeps secrets in a wrapper, reads them as late as it can
and drops the references, but a core dump or a process-memory read by the same user or root can still expose them. The
SSH password additionally sits in the environment of the `ssh` child for the duration of one connection. Treat the
machine that runs the tool as trusted with these secrets.

## Release verification

A release is built and published by a tag-triggered workflow whose jobs are separated by privilege: only the test, build
and SBOM jobs read the repository. The jobs that attest, publish and release hold only the permissions they need (the
attestation job `id-token` and `attestations`, the publish job `id-token`, the release job `contents: write`) and act
only on files whose SHA-256 the build or SBOM job recorded.

- **PyPI**: published through trusted publishing (OpenID Connect); no long-lived token exists. PyPI shows the
  publish attestation for each file.
- **GitHub Release**: carries the sdist, the wheel and `sbom.cdx.json` (CycloneDX, the runtime dependency graph).
- **Build provenance**: the sdist and the wheel are attested. Verify a downloaded one against the workflow that built it:

  ```bash
  gh attestation verify unifiwifioptimizer-<version>-py3-none-any.whl --repo jtauschl/unifiwifioptimizer
  ```

Source of truth for what you installed is the file you verify, not the version string it reports.

## Dependencies

There is exactly one runtime dependency, `pyyaml`. Development tools are pinned exactly, `uv.lock` and the hashed
build constraints are committed, and the build backend is installed with hashes. A weekly job audits the locked graph
and the build backend and scans the whole history for secrets.

## Scope

Bugs that could break any of the above are in scope: an accidental write, a credential leaked into a log or report, a
verification bypass, a controller URL or access-point host derived from untrusted input instead of your configuration,
an unintended outbound request, or a way to make the tool print attacker-controlled terminal escape sequences.
