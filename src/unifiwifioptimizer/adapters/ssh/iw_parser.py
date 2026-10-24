"""The remote scan script's output, turned into a `ScanPass`: total over any content, strict on structure.

The script prints three required sections (`===2GHZ===`, `===5GHZ===`, `===META===`) and an optional
`===POWER5G===` section; each band section starts
with `STATUS=<status>` and optionally `IFACE=<name>`, followed by the filtered `iw dev … scan` lines
(`BSS <mac>(on <iface>) …`, `freq: <MHz>`, `signal: <dBm> dBm`, `SSID: <text>`). Anything else inside a
band section is ignored — an access point is not a trusted party and firmware adds lines freely — while a
missing section or status is a protocol violation and a `ScanParseError`. One BSSID seen several times in
a pass (several `iw` attempts are concatenated) keeps its strongest reading.
"""

import re

from unifiwifioptimizer.domain.errors import ScanParseError
from unifiwifioptimizer.domain.models import Band
from unifiwifioptimizer.domain.scan import BandScan, BandScanStatus, PhyChannelPower, ScanMeta, ScanPass, ScanReading

MAX_READINGS_PER_BAND = 2000
MAX_SSID_BYTES = 32
MAX_META_VALUE_CHARS = 128
RSSI_MIN_EXCLUSIVE = -100.0
RSSI_MAX_EXCLUSIVE = 0.0
FREQUENCY_RANGE_MHZ = range(2400, 7200)

SECTION_2G = "===2GHZ==="
SECTION_5G = "===5GHZ==="
SECTION_META = "===META==="
SECTION_POWER_5G = "===POWER5G==="
_SECTIONS = {SECTION_2G: Band.GHZ_2, SECTION_5G: Band.GHZ_5}

_BSS_RE = re.compile(r"BSS ([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})(?:\(on (\S+)\))?")
_FREQ_RE = re.compile(r"\s*freq: (\d{3,5})(?:\.\d+)?\b")
_SIGNAL_RE = re.compile(r"\s*signal: (-?\d{1,3}(?:\.\d+)?) dBm")
_SSID_RE = re.compile(r"\s*SSID: (.*)")
_KEY_VALUE_RE = re.compile(r"([A-Z0-9_]{1,32})=(.*)")
_IFACE_RE = re.compile(r"[A-Za-z0-9._-]{1,15}")
_IW_ESCAPE_RE = re.compile(r"\\x([0-9a-fA-F]{2})|\\(.)")
_DFS_STATES = frozenset({"active", "ready", "unknown"})
_WATCHDOGS = frozenset({"timeout", "watcher"})
_PHY_RE = re.compile(r"PHY_INDEX=(\d{1,3})")
_CURRENT_FREQ_RE = re.compile(r"CURRENT_FREQ_MHZ=(\d{4})")
_POWER_RE = re.compile(r"\s*\* (\d{4})(?:\.0)? MHz \[(\d{1,3})\] \((\d{1,2}(?:\.\d)?) dBm\)(.*)")
MAX_POWER_ROWS = 64


def parse_scan_output(data: bytes) -> ScanPass:
    """Parse one remote run. The bytes are decoded with `surrogateescape` so an SSID's raw bytes survive
    up to the point where they are counted; everything shown later is re-decoded with replacement."""
    sections = _split_sections(data.decode("utf-8", errors="surrogateescape"))
    bands = tuple(_parse_band(band, sections[marker]) for marker, band in _SECTIONS.items())
    return ScanPass(
        bands=bands,
        meta=_parse_meta(sections[SECTION_META]),
        power_5g=_parse_power_5g(sections.get(SECTION_POWER_5G)),
    )


def _split_sections(text: str) -> dict[str, list[str]]:
    sections: dict[str, list[str]] = {}
    current: list[str] | None = None
    for line in text.splitlines():
        if line in _SECTIONS or line in (SECTION_META, SECTION_POWER_5G):
            if line == SECTION_POWER_5G and line in sections:
                # The power table is optional evidence: a doubled section is unknown, not a failed scan.
                sections[line] = ["STATUS=unknown"]
                current = []
                continue
            if line in sections:
                raise ScanParseError(f"section {line} appears twice")
            current = sections[line] = []
        elif current is not None:
            current.append(line)
        elif line.strip():
            raise ScanParseError("output before the first section")
    for marker in (*_SECTIONS, SECTION_META):
        if marker not in sections:
            raise ScanParseError(f"section {marker} missing")
    return sections


def _parse_power_5g(lines: list[str] | None) -> PhyChannelPower | None:
    if lines is None or len(lines) < 4 or len(lines) > MAX_POWER_ROWS + 3 or lines[0] != "STATUS=ok":
        return None
    phy = _PHY_RE.fullmatch(lines[1])
    current = _CURRENT_FREQ_RE.fullmatch(lines[2])
    if phy is None or current is None:
        return None
    current_mhz = int(current.group(1))
    if not 5000 < current_mhz < 5900:
        return None
    limits: dict[int, float] = {}
    for line in lines[3:]:
        match = _POWER_RE.fullmatch(line)
        if match is None:
            return None
        freq, channel, dbm = int(match.group(1)), int(match.group(2)), float(match.group(3))
        if freq != 5000 + 5 * channel or not 5000 < freq < 5900 or not 0 < dbm <= 40 or channel in limits:
            return None
        limits[channel] = dbm
    if not limits or current_mhz not in {5000 + 5 * channel for channel in limits}:
        return None
    return PhyChannelPower(
        phy_index=int(phy.group(1)), current_frequency_mhz=current_mhz, limits=tuple(sorted(limits.items()))
    )


def _parse_band(band: Band, lines: list[str]) -> BandScan:
    if not lines or not lines[0].startswith("STATUS="):
        raise ScanParseError(f"{band.value}: STATUS line missing")
    try:
        status = BandScanStatus(lines[0][len("STATUS=") :])
    except ValueError:
        raise ScanParseError(f"{band.value}: unknown STATUS") from None
    interface: str | None = None
    body = lines[1:]
    if body and body[0].startswith("IFACE="):
        name = body[0][len("IFACE=") :]
        interface = name if _IFACE_RE.fullmatch(name) else None
        body = body[1:]
    strongest: dict[str, ScanReading] = {}
    for reading in _readings(body):
        known = strongest.get(reading.bssid)
        if known is None or reading.rssi_dbm > known.rssi_dbm:
            strongest[reading.bssid] = reading
        if len(strongest) > MAX_READINGS_PER_BAND:
            raise ScanParseError(f"{band.value}: more than {MAX_READINGS_PER_BAND} networks")
    readings = tuple(sorted(strongest.values(), key=lambda r: r.bssid))
    if status is BandScanStatus.OK and not readings:
        status = BandScanStatus.EMPTY
    if status is not BandScanStatus.OK:
        # Lines after a non-OK status are not readings of this band, whatever the access point printed.
        readings = ()
    return BandScan(band=band, status=status, readings=readings, interface=interface)


def _readings(lines: list[str]) -> list[ScanReading]:
    """BSS blocks in order; a block without a usable signal yields nothing."""
    readings: list[ScanReading] = []
    bssid: str | None = None
    frequency: int | None = None
    signal: int | None = None
    ssid: str | None = None

    def flush() -> None:
        if bssid is not None and signal is not None:
            readings.append(ScanReading(bssid=bssid, rssi_dbm=signal, frequency_mhz=frequency, ssid=ssid))

    for line in lines:
        if m := _BSS_RE.match(line):
            flush()
            bssid, frequency, signal, ssid = m.group(1).lower(), None, None, None
        elif line.startswith("BSS "):
            # A BSS line without a usable address ends the previous block; its attributes belong to nobody.
            flush()
            bssid = None
        elif bssid is None:
            continue
        elif m := _FREQ_RE.match(line):
            megahertz = int(m.group(1))
            frequency = megahertz if megahertz in FREQUENCY_RANGE_MHZ else None
        elif m := _SIGNAL_RE.match(line):
            dbm = float(m.group(1))
            signal = round(dbm) if RSSI_MIN_EXCLUSIVE < dbm < RSSI_MAX_EXCLUSIVE else None
        elif m := _SSID_RE.match(line):
            ssid = _ssid(m.group(1))
    flush()
    return readings


def _ssid(printed: str) -> str | None:
    """`iw` prints non-printable SSID bytes as `\\xHH` and a backslash as `\\\\`; the WLAN's 32-byte limit
    applies to the bytes, not to their escaped spelling. The bytes are rebuilt, capped, and read as UTF-8
    with replacement — the report layer decides what is safe to show."""

    def replace(match: re.Match[str]) -> str:
        if match.group(1) is not None:
            return chr(int(match.group(1), 16))
        return match.group(2)

    original = printed.encode("utf-8", errors="surrogateescape").decode("latin-1")
    raw = _IW_ESCAPE_RE.sub(replace, original).encode("latin-1")
    if not raw or len(raw) > MAX_SSID_BYTES:
        return None
    return raw.decode("utf-8", errors="replace")


def _shown(text: str) -> str:
    return text.encode("utf-8", errors="surrogateescape").decode("utf-8", errors="replace")


def _parse_meta(lines: list[str]) -> ScanMeta:
    values: dict[str, str] = {}
    for line in lines:
        if m := _KEY_VALUE_RE.fullmatch(line):
            values.setdefault(m.group(1), m.group(2)[:MAX_META_VALUE_CHARS])
    model = _shown(values.get("MODEL_NAME", "")).strip() or None
    dfs = values.get("DFS_CAC_5G")
    watchdog = values.get("WATCHDOG")
    return ScanMeta(
        model_name=model,
        dfs_cac_5g=dfs if dfs in _DFS_STATES else None,
        watchdog=watchdog if watchdog in _WATCHDOGS else None,
    )
