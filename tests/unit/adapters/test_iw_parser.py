import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from unifiwifioptimizer.adapters.ssh.iw_parser import (
    MAX_READINGS_PER_BAND,
    MAX_SSID_BYTES,
    parse_scan_output,
)
from unifiwifioptimizer.domain.errors import ScanParseError
from unifiwifioptimizer.domain.models import Band
from unifiwifioptimizer.domain.scan import BandScanStatus

SAMPLE = b"""===2GHZ===
STATUS=ok
IFACE=apcli0
BSS 02:00:00:00:00:a1(on apcli0) -- associated
\tfreq: 2437
\tsignal: -58.00 dBm
\tSSID: Home
BSS 02:00:00:00:00:B2(on apcli0)
\tfreq: 2412.0
\tsignal: -71.50 dBm
\tSSID: Neighbour
BSS 02:00:00:00:00:a1(on apcli0)
\tsignal: -55.00 dBm
\tSSID: Home
===5GHZ===
STATUS=ok
IFACE=apclii0
BSS 02:00:00:00:00:c3(on apclii0)
\tfreq: 5500
\tsignal: -66.00 dBm
===META===
MODEL_NAME=U6 Lite
DFS_CAC_5G=ready
WATCHDOG=timeout
"""


def test_sample_output_parses_both_bands_and_the_meta_block() -> None:
    result = parse_scan_output(SAMPLE)
    two = result.band(Band.GHZ_2)
    five = result.band(Band.GHZ_5)
    assert two is not None and five is not None
    assert two.status is BandScanStatus.OK and two.interface == "apcli0"
    assert [(r.bssid, r.rssi_dbm, r.frequency_mhz, r.ssid) for r in two.readings] == [
        ("02:00:00:00:00:a1", -55, None, "Home"),
        ("02:00:00:00:00:b2", -72, 2412, "Neighbour"),
    ]
    assert five.readings[0].frequency_mhz == 5500 and five.readings[0].ssid is None
    assert (
        result.meta.model_name == "U6 Lite" and result.meta.dfs_cac_5g == "ready" and result.meta.watchdog == "timeout"
    )


def test_the_strongest_reading_wins_for_a_repeated_bssid_even_if_it_carries_no_frequency() -> None:
    two = parse_scan_output(SAMPLE).band(Band.GHZ_2)
    assert two is not None and two.readings[0].rssi_dbm == -55 and two.readings[0].frequency_mhz is None


@pytest.mark.parametrize(
    ("text", "message"),
    [
        (b"", "section ===2GHZ=== missing"),
        (b"===2GHZ===\nSTATUS=ok\n===META===\n", "section ===5GHZ=== missing"),
        (b"===2GHZ===\nSTATUS=ok\n===5GHZ===\nSTATUS=ok\n", "section ===META=== missing"),
        (b"===2GHZ===\nSTATUS=ok\n===2GHZ===\nSTATUS=ok\n===5GHZ===\nSTATUS=ok\n===META===\n", "appears twice"),
        (b"garbage\n===2GHZ===\nSTATUS=ok\n===5GHZ===\nSTATUS=ok\n===META===\n", "output before the first section"),
        (b"===2GHZ===\nBSS 02:00:00:00:00:a1\n===5GHZ===\nSTATUS=ok\n===META===\n", "2g: STATUS line missing"),
        (b"===2GHZ===\nSTATUS=great\n===5GHZ===\nSTATUS=ok\n===META===\n", "2g: unknown STATUS"),
    ],
)
def test_structural_violations_are_parse_errors(text: bytes, message: str) -> None:
    with pytest.raises(ScanParseError, match=message):
        parse_scan_output(text)


def test_statuses_pass_through_and_ok_without_readings_becomes_empty() -> None:
    text = b"===2GHZ===\nSTATUS=no_radio\n===5GHZ===\nSTATUS=ok\nIFACE=apclii0\n===META===\n"
    result = parse_scan_output(text)
    assert result.band(Band.GHZ_2).status is BandScanStatus.NO_RADIO  # type: ignore[union-attr]
    assert result.band(Band.GHZ_5).status is BandScanStatus.EMPTY  # type: ignore[union-attr]
    assert result.meta.model_name is None and result.meta.dfs_cac_5g is None and result.meta.watchdog is None


def test_out_of_range_values_drop_the_field_or_the_reading_not_the_pass() -> None:
    body = (
        b"BSS 02:00:00:00:00:01(on x)\n\tfreq: 99999\n\tsignal: -120.00 dBm\n"
        b"BSS 02:00:00:00:00:02(on x)\n\tfreq: 1\n\tsignal: 5.00 dBm\n"
        b"BSS 02:00:00:00:00:03(on x)\n\tfreq: 2412\n\tsignal: -0.4 dBm\n"
        b"BSS 02:00:00:00:00:04(on x)\n\tfreq: 2412\n\tsignal: -99.9 dBm\n\tSSID: "
        + b"x"
        * (MAX_SSID_BYTES + 1)
        + b"\n"
        b"BSS zz:00:00:00:00:05(on x)\n\tsignal: -50.00 dBm\n"
        b"\tsignal: -40.00 dBm\n"
        b"BSS 02:00:00:00:00:06\n\tsignal: -60 dBm\n\tSSID: " + "ü".encode() * 16 + b"\n"
    )
    text = b"===2GHZ===\nSTATUS=ok\n" + body + b"===5GHZ===\nSTATUS=ok\n===META===\nMODEL_NAME=\nDFS_CAC_5G=odd\n"
    two = parse_scan_output(text).band(Band.GHZ_2)
    assert two is not None
    assert [(r.bssid, r.rssi_dbm, r.frequency_mhz, r.ssid) for r in two.readings] == [
        ("02:00:00:00:00:03", 0, 2412, None),
        ("02:00:00:00:00:04", -100, 2412, None),
        ("02:00:00:00:00:06", -60, None, "ü" * 16),
    ]


def test_more_networks_than_the_cap_is_a_parse_error() -> None:
    blocks = b"".join(
        b"BSS 02:00:%02x:%02x:00:01(on x)\n\tsignal: -70 dBm\n" % (i // 256, i % 256)
        for i in range(MAX_READINGS_PER_BAND + 1)
    )
    text = b"===2GHZ===\nSTATUS=ok\n" + blocks + b"===5GHZ===\nSTATUS=ok\n===META===\n"
    with pytest.raises(ScanParseError, match=f"more than {MAX_READINGS_PER_BAND} networks"):
        parse_scan_output(text)
    fewer = b"".join(
        b"BSS 02:00:%02x:%02x:00:01(on x)\n\tsignal: -70 dBm\n" % (i // 256, i % 256)
        for i in range(MAX_READINGS_PER_BAND)
    )
    assert (
        len(
            parse_scan_output(b"===2GHZ===\nSTATUS=ok\n" + fewer + b"===5GHZ===\nSTATUS=ok\n===META===\n")
            .bands[0]
            .readings
        )
        == MAX_READINGS_PER_BAND
    )


def test_undecodable_bytes_and_unknown_lines_are_tolerated() -> None:
    text = (
        b"===2GHZ===\nSTATUS=ok\n\xff\xfe weird\nBSS 02:00:00:00:00:01(on x)\n\tTSF: 1 usec\n\tsignal: -61 dBm\n"
        b"\tSSID: \xff\xfe\n===5GHZ===\nSTATUS=failed\n===META===\nJUNK\n"
    )
    two = parse_scan_output(text).band(Band.GHZ_2)
    assert two is not None and two.readings[0].rssi_dbm == -61 and two.readings[0].ssid == "��"


band_body = st.lists(
    st.one_of(
        st.builds(
            lambda mac, freq, sig, ssid: f"BSS {mac}(on x)\n\tfreq: {freq}\n\tsignal: {sig:.2f} dBm\n\tSSID: {ssid}\n",
            st.from_regex(r"[0-9a-f]{2}(:[0-9a-f]{2}){5}", fullmatch=True),
            st.integers(0, 99999),
            st.floats(-150, 50, allow_nan=False, allow_infinity=False),
            st.text(max_size=40),
        ),
        st.text(max_size=80)
        .map(lambda t: t.replace("\n", " "))
        .filter(lambda t: not t.startswith("==="))
        .map(lambda t: t + "\n"),
    ),
    max_size=30,
)


@settings(max_examples=300, deadline=None)
@given(
    status_2=st.sampled_from([s.value for s in BandScanStatus]),
    body_2=band_body,
    body_5=band_body,
    meta=st.text(max_size=200),
)
def test_parser_is_total_over_any_band_content(status_2: str, body_2: list[str], body_5: list[str], meta: str) -> None:
    text = (
        f"===2GHZ===\nSTATUS={status_2}\n"
        + "".join(body_2)
        + "===5GHZ===\nSTATUS=ok\n"
        + "".join(body_5)
        + "===META===\n"
        + meta
    ).encode("utf-8", errors="surrogatepass")
    try:
        result = parse_scan_output(text)
    except ScanParseError:
        # Random content may spell a section marker; refusing it is the other half of totality.
        return
    for band in result.bands:
        assert len(band.readings) <= MAX_READINGS_PER_BAND
        for reading in band.readings:
            assert -100 < reading.rssi_dbm < 0 or reading.rssi_dbm in (0, -100)
            assert reading.frequency_mhz is None or 2400 <= reading.frequency_mhz < 7200
            # The cap applies to the raw bytes; a replacement character may stand for one undecodable byte.
            assert reading.ssid is None or len(reading.ssid) <= MAX_SSID_BYTES


def test_interface_names_are_validated_and_iw_escapes_are_undone_before_the_ssid_cap() -> None:
    text = (
        b"===2GHZ===\nSTATUS=ok\nIFACE=../etc\nBSS 02:00:00:00:00:01(on x)\n\tsignal: -50 dBm\n\tSSID: "
        + b"\\xc3\\xa4" * 16
        + b"\n===5GHZ===\nSTATUS=ok\nIFACE=apclii0\nBSS 02:00:00:00:00:02(on x)\n\tsignal: -60 dBm\n"
        b"\tSSID: a\\\\b\\x00c\n===META===\n"
    )
    result = parse_scan_output(text)
    two, five = result.bands
    assert two.interface is None and five.interface == "apclii0"
    # 16 times `\xc3\xa4` is 64 escaped characters but 32 bytes of SSID: within the limit once rebuilt.
    assert two.readings[0].ssid == "ä" * 16
    assert five.readings[0].ssid == "a\\b\x00c"


def test_readings_after_a_non_ok_status_are_not_readings() -> None:
    text = (
        b"===2GHZ===\nSTATUS=failed\nBSS 02:00:00:00:00:01(on x)\n\tsignal: -50 dBm\n"
        b"===5GHZ===\nSTATUS=interface_down\nBSS 02:00:00:00:00:02(on x)\n\tsignal: -50 dBm\n===META===\n"
    )
    result = parse_scan_output(text)
    assert result.bands[0].status is BandScanStatus.FAILED and result.bands[0].readings == ()
    assert result.bands[1].status is BandScanStatus.INTERFACE_DOWN and result.bands[1].readings == ()
