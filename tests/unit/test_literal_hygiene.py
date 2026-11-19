"""Gate: no real hardware address in the text files listed in `SCANNED`; only synthetic and generic examples.

The fixture gate covers the JSON fixtures; this one covers the other places a MAC copied from a live site could land:
sources, tests, documentation, scripts, the Docker harness, workflow and template files, the top-level documents and
the starters. It does not read the dependency pins (`uv.lock`, `build-constraints.*`: package names, versions and
hashes), `LICENSE`, the top-level dotfiles other than `.gitleaksignore`, files with a binary or image suffix, cache
folders, or anything behind a symlinked folder (`os.walk` does not follow them). A folder that cannot be read fails
the gate. It reads the working tree, not the index (the lower-bound job runs the unit tests in a copy without `.git`),
so an ignored local file inside a scanned folder is read too.

What it matches: a run of six to eight colon-separated hex pairs (six are an address, seven are an address next to a
two-digit field or label, eight an address next to two fields or an EUI-64) and a bare twelve-hex-digit token (the form
of a UniFi serial). The runs are candidates, not proof; a run is allowed only when every six-octet window of it is
synthetic (prefix `02:00:00:00:`) or one of the generic examples, so `ab:<synthetic mac>` and
`<synthetic prefix>:ab:cd:ef` are flagged. A valid IPv6 literal (`fe80::a1:b2:c3:d4:e5:f6`) is blanked out first. It
does not match a dash or Cisco-dotted spelling. A twelve-character token that is hex (a Git or Docker short ID) is
treated like a serial: write it with seven or forty characters, or add it to `GENERIC_BARE`.
"""

import ipaddress
import os
import re
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[2]
SCANNED = (
    "src", "tests", "docs", "scripts", "docker", ".github", "README.md", "CHANGELOG.md", "SECURITY.md",
    "CONTRIBUTING.md", "CODE_OF_CONDUCT.md", "pyproject.toml", ".gitleaksignore", "config.example.yaml",
    "config.minimal.yaml", "dev",
)  # fmt: skip
SKIPPED_DIRS = {"__pycache__", ".venv", ".pytest_cache", ".mypy_cache", ".ruff_cache"}
SKIPPED_SUFFIXES = {".pyc", ".png", ".jpg", ".psd", ".whl", ".gz"}

# A run of colon-separated hex pairs, bounded by characters that are not alphanumeric (so the `ac` of `mac:` is no
# octet). A run of six to eight pairs is reported: six are an address, seven are an address next to a two-digit field
# or label (`<mac>:07`, `ab:<mac>`), eight are an EUI-64 derived from one; a fingerprint has sixteen or more.
OCTET_RUN = re.compile(r"(?<![0-9A-Za-z])(?:[0-9A-Fa-f]{2}:)*[0-9A-Fa-f]{2}(?![0-9A-Za-z])")
ADDRESS_OCTETS = range(6, 9)
IPV6_LITERAL = re.compile(r"(?<![0-9A-Za-z:])[0-9A-Fa-f:]*::[0-9A-Fa-f:]*(?![0-9A-Za-z:])")
# The same address without separators, as a UniFi serial number: twelve hex digits (all digits included) between
# non-alphanumerics.
BARE_MAC = re.compile(r"(?<![0-9A-Za-z])[0-9A-Fa-f]{12}(?![0-9A-Za-z])")
# The locally administered prefix of the anonymizer's synthetic addresses.
SYNTHETIC_PREFIX = "02:00:00:00:"
# Generic examples that name no device. Placeholders and the 0xdeadbeef pattern carry the locally administered bit or
# are no vendor's; the f4:92:bf entries are made-up addresses of the anonymizer's own tests (a vendor prefix with a
# counting suffix, not any device of this project). Keep this set small: a rule such as "any locally administered
# address passes" would let real randomised client addresses through.
GENERIC = frozenset(
    {
        "aa:aa:aa:aa:aa:aa", "aa:aa:aa:aa:aa:ab", "aa:bb:cc:dd:ee:ff", "aa:bb:cc:dd:ee:01", "de:ad:be:ef:00:01",
        "f4:92:bf:12:34:56", "f4:92:bf:12:34:57", "f4:92:bf:00:00:01",
    }
)  # fmt: skip
# The bare tokens in the tree that are format examples, anonymizer test inputs or a vendor article number; the bare
# form of the synthetic prefix needs no entry.
GENERIC_BARE = frozenset({"aabbccddeeff", "f492bf123456", "115000166827"})
SYNTHETIC_BARE_PREFIX = SYNTHETIC_PREFIX.replace(":", "")


def _raise(error: OSError) -> None:
    """A directory that cannot be read fails the gate; `os.walk` would skip it silently."""
    raise error


def scanned_files() -> Iterator[Path]:
    for name in SCANNED:
        root = ROOT / name
        if root.is_file():
            yield root
        elif root.is_dir():
            for directory, names, files in os.walk(root, onerror=_raise):
                names[:] = sorted(name for name in names if name not in SKIPPED_DIRS)
                for name in sorted(files):
                    if Path(name).suffix not in SKIPPED_SUFFIXES:
                        yield Path(directory) / name


def _blank_ipv6(text: str) -> str:
    def blank(match: re.Match[str]) -> str:
        try:
            ipaddress.IPv6Address(match.group(0))
        except ValueError:
            return match.group(0)
        return " " * len(match.group(0))

    return IPV6_LITERAL.sub(blank, text) if "::" in text else text


def _allowed(window: str) -> bool:
    return window.startswith(SYNTHETIC_PREFIX) or window in GENERIC


def foreign_addresses(text: str) -> list[str]:
    text = _blank_ipv6(text)
    colon = []
    for run in OCTET_RUN.finditer(text):
        octets = run.group(0).lower().split(":")
        if len(octets) in ADDRESS_OCTETS and not all(
            _allowed(":".join(octets[start : start + 6])) for start in range(len(octets) - 5)
        ):
            colon.append(":".join(octets))
    bare = (match.group(0).lower() for match in BARE_MAC.finditer(text))
    return colon + [
        token for token in bare if not token.startswith(SYNTHETIC_BARE_PREFIX) and token not in GENERIC_BARE
    ]


# Written out a second time on purpose: dropping a root from `SCANNED` must fail a test, not silently shrink the gate.
REQUIRED_ROOTS = (
    "src", "tests", "docs", "scripts", "docker", ".github", "README.md", "CHANGELOG.md", "SECURITY.md",
    "CONTRIBUTING.md", "CODE_OF_CONDUCT.md", "pyproject.toml", ".gitleaksignore", "config.example.yaml",
    "config.minimal.yaml", "dev",
)  # fmt: skip


def test_a_folder_that_cannot_be_read_fails_the_scan_instead_of_shrinking_it(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    (tmp_path / "scanned" / "inner").mkdir(parents=True)
    (tmp_path / "scanned" / "inner" / "f.txt").write_text("x")
    this = sys.modules[__name__]
    monkeypatch.setattr(this, "ROOT", tmp_path)
    monkeypatch.setattr(this, "SCANNED", ("scanned",))
    assert [path.name for path in scanned_files()] == ["f.txt"]
    real_scandir = os.scandir

    def scandir(path: str = ".") -> object:
        if str(path).endswith("inner"):
            raise PermissionError(13, "denied", str(path))
        return real_scandir(path)

    monkeypatch.setattr(os, "scandir", scandir)
    with pytest.raises(PermissionError):
        list(scanned_files())


@pytest.mark.parametrize("name", REQUIRED_ROOTS)
def test_every_required_root_is_scanned_and_yields_a_file(name: str) -> None:
    assert name in SCANNED
    names = {path.relative_to(ROOT).as_posix() for path in scanned_files()}
    assert name in names or any(entry.startswith(f"{name}/") for entry in names)


# Built from octets, so that this file carries no address the gate would have to allow.
DEVICE_LIKE = ":".join(("1a", "2b", "3c", "4d", "5e", "6f"))
DEVICE_BARE = DEVICE_LIKE.replace(":", "")
# Ambiguous runs next to the synthetic prefix, built from octets for the same reason.
SYNTHETIC_THEN_FIELDS = ":".join(("02", "00", "00", "00", "ab", "cd", "ef"))
FIELD_THEN_SYNTHETIC = ":".join(("ab", "02", "00", "00", "00", "00", "04"))
SYNTHETIC_THEN_FIELD = ":".join(("02", "00", "00", "00", "00", "04", "05"))
DIGIT_SERIAL = "".join(("84", "12", "34", "56", "78", "90"))
SHORT_ID = "".join(("01", "23", "45", "67", "89", "ab"))


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (f"pin {DEVICE_LIKE} here", [DEVICE_LIKE]),
        (f"KEY {DEVICE_LIKE.upper()}", [DEVICE_LIKE]),
        (f"host_keys:\n  {DEVICE_LIKE}: SHA256:x", [DEVICE_LIKE]),
        (f"key:{DEVICE_LIKE}", [DEVICE_LIKE]),
        (f'"{DEVICE_LIKE}"', [DEVICE_LIKE]),
        (f"serial {DEVICE_BARE.upper()} model", [DEVICE_BARE]),
        (f"serial {DIGIT_SERIAL} model", [DIGIT_SERIAL]),
        ("articles/115000166827-Guide", []),
        (f"serial {SYNTHETIC_BARE_PREFIX}0004", []),
        (f"short id {SHORT_ID}", [SHORT_ID]),
        ("sha 0123456789abcdef0123456789abcdef01234567 and 0123abc", []),
        (f"iface:{DEVICE_LIKE}", [DEVICE_LIKE]),
        (f"{DEVICE_LIKE}:ap-1", [DEVICE_LIKE]),
        (f"{DEVICE_LIKE}:7", [DEVICE_LIKE]),
        ("02:00:00:00:00:04 and de:ad:be:ef:00:01", []),
        ("17:0f:78:6f:42:69:5d:63:41:28:d1:6b:db:8f:dd:87", []),
        (f"{DEVICE_LIKE}:07", [f"{DEVICE_LIKE}:07"]),
        (f"07:{DEVICE_LIKE}", [f"07:{DEVICE_LIKE}"]),
        (f"mac:{DEVICE_LIKE}", [DEVICE_LIKE]),
        (f"ap_mac:{DEVICE_LIKE}", [DEVICE_LIKE]),
        (f"{DEVICE_LIKE}:ac", [f"{DEVICE_LIKE}:ac"]),
        (f"{DEVICE_LIKE}:07:08", [f"{DEVICE_LIKE}:07:08"]),
        (f"{DEVICE_LIKE}:07:08:09", []),
        (SYNTHETIC_THEN_FIELDS, [SYNTHETIC_THEN_FIELDS]),
        (FIELD_THEN_SYNTHETIC, [FIELD_THEN_SYNTHETIC]),
        (SYNTHETIC_THEN_FIELD, [SYNTHETIC_THEN_FIELD]),
        ("fe80::a1:b2:c3:d4:e5:f6 and ::1", []),
        ("a1:b2:c3:d4:e5:f6:07:08:09", []),
        ("aa:bb:cc:dd:ee:01 aabbccddeeff", []),
        (f"x{DEVICE_BARE}", []),
    ],
)
def test_the_patterns_flag_a_device_address_and_leave_fingerprints_and_examples_alone(
    text: str, expected: list[str]
) -> None:
    assert foreign_addresses(text) == expected


def test_no_file_in_the_scanned_places_holds_an_address_that_could_belong_to_a_device() -> None:
    offenders = {
        f"{path.relative_to(ROOT).as_posix()}: {mac}"
        for path in scanned_files()
        for mac in foreign_addresses(path.read_text(errors="replace"))
    }
    assert not offenders, sorted(offenders)
