"""Tests for possible_beaconing, run with: py tests/test_beaconing.py"""
import contextlib
import io
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from scapy.all import rdpcap  # noqa: E402

from analyze import possible_beaconing  # noqa: E402


def suspicious_section(pcap_name):
    """Run the detector and return the lines of the 'Possible beaconing' section."""
    packets = rdpcap(str(ROOT / "captures" / pcap_name))
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        possible_beaconing(packets)
    lines = buf.getvalue().splitlines()
    start = next(i for i, l in enumerate(lines) if l.startswith("Possible beaconing"))
    end = next(i for i, l in enumerate(lines) if l.startswith("Top "))
    return [l for l in lines[start + 1:end] if l.strip()]


def test_synthetic_beacon_is_flagged():
    section = suspicious_section("synthetic.pcap")
    assert any("192.168.1.30" in l and "93.184.216.34" in l and ":7007" in l
               for l in section), section


def test_clean_traffic_flags_nothing():
    section = suspicious_section("2026-08-10-traffic.pcap")
    assert section == ["  (nothing found with these parameters)"], section


def test_amos_polling_is_flagged():
    section = suspicious_section("2026-09-10-AMOS-Stealer-infection-traffic.pcap")
    assert any("10.9.10.26" in l and "165.22.199.85" in l and ":80 " in l
               for l in section), section


def test_jitter_beacons_are_flagged():
    section = suspicious_section("jitter.pcap")
    for n in range(35, 40):
        assert any("192.168.1.30" in l and f"93.184.216.{n} " in l and ":7007" in l
                   for l in section), (n, section)


if __name__ == "__main__":
    test_synthetic_beacon_is_flagged()
    test_clean_traffic_flags_nothing()
    test_amos_polling_is_flagged()
    test_jitter_beacons_are_flagged()
    print("OK: 4 tests passed")
