"""Tests for possible_beaconing and the connection-direction helpers.

Run with: py tests/test_beaconing.py
Needs captures/synthetic.pcap, jitter.pcap and direction.pcap (generate them
with tests/make_synthetic.py, make_jitter.py, make_direction.py) and the real
captures listed below in captures/.
"""
import contextlib
import io
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from scapy.all import IP, TCP, Ether, rdpcap  # noqa: E402

from analyze import (  # noqa: E402
    DEFAULT_HOME_NETS,
    connection_direction,
    find_initiators,
    parse_home_nets,
    possible_beaconing,
)

OUTBOUND = "Possible beaconing"
INBOUND = "Regular inbound visits"

_cache = {}


def run(pcap_name, home_nets=None):
    """Run the detector and return its printed output as a list of lines."""
    if pcap_name not in _cache:
        _cache[pcap_name] = rdpcap(str(ROOT / "captures" / pcap_name))
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        possible_beaconing(_cache[pcap_name], home_nets=home_nets)
    return buf.getvalue().splitlines()


def section(pcap_name, heading, home_nets=None):
    """Lines of the section whose heading starts with `heading` (up to the next blank line)."""
    lines = run(pcap_name, home_nets)
    start = next(i for i, l in enumerate(lines) if l.startswith(heading))
    end = next((i for i in range(start + 1, len(lines)) if not lines[i].strip()), len(lines))
    return lines[start + 1:end]


def has(lines, client, server, port):
    return any(f"{client} " in l and f"{server} " in l and f":{port} " in l for l in lines)


# --- existing behaviour must not change -------------------------------------

def test_synthetic_beacon_is_flagged():
    out = section("synthetic.pcap", OUTBOUND)
    assert has(out, "192.168.1.30", "93.184.216.34", 7007), out


def test_clean_traffic_flags_nothing():
    out = section("2026-08-10-traffic.pcap", OUTBOUND)
    assert out == ["  (nothing found with these parameters)"], out


def test_amos_polling_is_flagged():
    out = section("2026-09-10-AMOS-Stealer-infection-traffic.pcap", OUTBOUND)
    assert has(out, "10.9.10.26", "165.22.199.85", 80), out


def test_netsupport_c2_is_flagged():
    out = section("2026-02-28-traffic-analysis-exercise.pcap", OUTBOUND)
    assert has(out, "10.2.28.88", "45.131.214.85", 443), out


def test_jitter_beacons_are_flagged():
    out = section("jitter.pcap", OUTBOUND)
    for n in range(35, 40):
        assert has(out, "192.168.1.30", f"93.184.216.{n}", 7007), (n, out)


# --- direction ---------------------------------------------------------------

def test_outbound_beacons_are_flagged():
    out = section("direction.pcap", OUTBOUND)
    assert has(out, "192.168.1.30", "93.184.216.34", 443), out
    # kept-alive connection with no SYN in the capture: client found by port
    assert has(out, "10.0.0.5", "45.131.214.85", 443), out


def test_inbound_and_internal_are_not_beaconing():
    out = section("direction.pcap", OUTBOUND)
    assert not any("185.220.101.4" in l for l in out), out   # inbound scanner
    assert not any("115.231.78.11" in l for l in out), out   # scanner -> public server
    assert not any("192.168.1.1 " in l for l in out), out    # internal
    assert len(out) == 2, out


def test_inbound_scanner_is_listed_as_visit():
    out = section("direction.pcap", INBOUND)
    assert has(out, "185.220.101.4", "192.168.1.80", 3389), out


def test_home_net_option_makes_public_server_ours():
    home = DEFAULT_HOME_NETS + parse_home_nets("81.84.10.20")
    out = section("direction.pcap", INBOUND, home)
    assert has(out, "115.231.78.11", "81.84.10.20", 22), out
    assert not any("115.231.78.11" in l for l in section("direction.pcap", OUTBOUND, home))


def test_public_server_scanners_are_inbound_not_beaconing():
    """2026-03-17: a week of internet scans hitting one public web server."""
    name = "2026-03-17-seven-days-of-scans-and-probes-and-web-traffic-hitting-my-web-server.pcap"
    home = parse_home_nets("203.161.44.208")
    assert section(name, OUTBOUND, home) == ["  (nothing found with these parameters)"]
    assert has(section(name, INBOUND, home), "95.214.52.233", "203.161.44.208", 3629)


def test_warning_when_no_host_is_home():
    lines = run("direction.pcap", parse_home_nets("172.31.99.0/24"))
    assert any("WARNING: no host in this capture is in the home network" in l for l in lines), lines


def test_initiator_rules():
    c, s = ("10.0.0.1", 50000), ("8.8.8.8", 443)

    def pkt(src, dst, flags, t):
        p = Ether() / IP(src=src[0], dst=dst[0]) / TCP(sport=src[1], dport=dst[1], flags=flags)
        p.time = t
        return p

    # SYN decides, even if the server's packet is seen first
    (client, server, method), = find_initiators([pkt(s, c, "A", 0), pkt(c, s, "S", 1)]).values()
    assert (client, server, method) == (c, s, "syn")
    # only a SYN-ACK: its sender is the server
    (client, server, method), = find_initiators([pkt(s, c, "SA", 0)]).values()
    assert (client, server, method) == (c, s, "synack")
    # no handshake, server speaks first: lower port is still the server
    (client, server, method), = find_initiators([pkt(s, c, "PA", 0)]).values()
    assert (client, server, method) == (c, s, "port")


def test_connection_direction():
    home = DEFAULT_HOME_NETS
    assert connection_direction("192.168.1.5", "8.8.8.8", home) == "outbound"
    assert connection_direction("8.8.8.8", "10.1.2.3", home) == "inbound"
    assert connection_direction("172.16.0.5", "192.168.1.1", home) == "internal"
    assert connection_direction("1.1.1.1", "8.8.8.8", home) == "external"
    assert connection_direction("172.32.0.1", "8.8.8.8", home) == "external"  # just outside 172.16/12


if __name__ == "__main__":
    tests = [f for name, f in sorted(globals().items()) if name.startswith("test_")]
    for test in tests:
        test()
    print(f"OK: {len(tests)} tests passed")
