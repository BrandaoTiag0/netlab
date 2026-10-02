"""Tests for ip_without_dns.

Run with: py tests/test_no_dns.py
Needs captures/synthetic.pcap (generate it with tests/make_synthetic.py) and
the real XWorm and AMOS captures in captures/.
"""
import contextlib
import io
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from scapy.all import rdpcap  # noqa: E402

from analyze import ip_without_dns  # noqa: E402

HEADING = "Connections to IPs without prior DNS:"


def flagged(pcap_name):
    """Rows printed by ip_without_dns, without the heading and the trailing summary line."""
    packets = rdpcap(str(ROOT / "captures" / pcap_name))
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        ip_without_dns(packets)
    lines = buf.getvalue().splitlines()
    start = lines.index(HEADING)
    return [l for l in lines[start + 1:] if " -> " in l]


def has(rows, src, dst, port):
    return any(l.split()[0] == src and f"{dst}:{port} " in l for l in rows)


def test_xworm_is_flagged():
    rows = flagged("2026-09-08-XWorm-post-infection-traffic.pcap")
    assert has(rows, "10.9.8.128", "43.228.157.141", 7007), rows
    assert "[unusual port]" in next(l for l in rows if "43.228.157.141" in l), rows


def test_amos_flags_nothing():
    rows = flagged("2026-09-10-AMOS-Stealer-infection-traffic.pcap")
    assert rows == [], rows


def test_synthetic_beacon_is_flagged():
    rows = flagged("synthetic.pcap")
    assert has(rows, "192.168.1.30", "93.184.216.34", 7007), rows


if __name__ == "__main__":
    tests = [f for name, f in sorted(globals().items()) if name.startswith("test_")]
    for test in tests:
        test()
    print(f"OK: {len(tests)} tests passed")
