"""Generate captures/direction.pcap: regular traffic in every direction.

Home network for this capture: the private ranges (default) PLUS the public
server 81.84.10.20, i.e. run with --home-net 10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,81.84.10.20/32

1. OUTBOUND beacon, new connection each time (SYN):
   192.168.1.30 -> 93.184.216.34:443 every 30s, 25 times. Must be flagged.
2. OUTBOUND beacon inside ONE kept-alive connection whose SYN is not in the
   capture (it started before the recording): 10.0.0.5:50123 <-> 45.131.214.85:443,
   client heartbeat every 60s + server reply. Must be flagged (initiator found by port).
3. INBOUND scanner hitting a home server that has a PUBLIC IP:
   115.231.78.11 -> 81.84.10.20:22 every 120s, 20 times, server replies SYN-ACK.
   Must NOT be flagged as beaconing; must show up as an inbound visit.
4. INBOUND scanner hitting a private host (port-forwarded):
   185.220.101.4 -> 192.168.1.80:3389 every 300s, 15 times. Same as 3.
5. INTERNAL regular traffic: 192.168.1.30 -> 192.168.1.1:445 every 30s, 25 times.
   Must NOT be flagged.
"""
import random
from pathlib import Path

from scapy.all import IP, TCP, Ether, wrpcap

random.seed(42)

OUT = Path(__file__).resolve().parent.parent / "captures" / "direction.pcap"
packets = []
t0 = 1_700_000_000.0


def add(pkt, t):
    pkt.time = t
    packets.append(pkt)


def handshake_beacon(client, server, dport, interval, count, start, sport_base):
    """New TCP connection per beacon: SYN, SYN-ACK, ACK, client payload."""
    t = start
    for i in range(count):
        sport = sport_base + i
        add(Ether() / IP(src=client, dst=server) / TCP(sport=sport, dport=dport, flags="S", seq=1000), t)
        add(Ether() / IP(src=server, dst=client) / TCP(sport=dport, dport=sport, flags="SA", seq=2000, ack=1001), t + 0.03)
        add(Ether() / IP(src=client, dst=server) / TCP(sport=sport, dport=dport, flags="A", seq=1001, ack=2001), t + 0.031)
        add(Ether() / IP(src=client, dst=server) / TCP(sport=sport, dport=dport, flags="PA", seq=1001, ack=2001) / b"hello", t + 0.032)
        add(Ether() / IP(src=server, dst=client) / TCP(sport=dport, dport=sport, flags="PA", seq=2001, ack=1006) / b"ok", t + 0.06)
        t += interval * random.uniform(0.95, 1.05)


# (1) outbound beacon, new connection each time
handshake_beacon("192.168.1.30", "93.184.216.34", 443, 30, 25, t0, 41000)

# (2) outbound beacon in a kept-alive connection, no SYN in the capture
client, server, sport, dport = "10.0.0.5", "45.131.214.85", 50123, 443
t = t0 + 5
for i in range(25):
    add(Ether() / IP(src=client, dst=server) / TCP(sport=sport, dport=dport, flags="PA", seq=5000 + i * 10) / b"heartbeat!", t)
    add(Ether() / IP(src=server, dst=client) / TCP(sport=dport, dport=sport, flags="PA", seq=9000 + i * 5) / b"ack!!", t + 0.05)
    add(Ether() / IP(src=client, dst=server) / TCP(sport=sport, dport=dport, flags="A"), t + 0.051)
    t += 60

# (3) inbound scanner -> home server with a public IP
handshake_beacon("115.231.78.11", "81.84.10.20", 22, 120, 20, t0 + 7, 43000)

# (4) inbound scanner -> private host
handshake_beacon("185.220.101.4", "192.168.1.80", 3389, 300, 15, t0 + 9, 44000)

# (5) internal regular traffic
handshake_beacon("192.168.1.30", "192.168.1.1", 445, 30, 25, t0 + 11, 45000)

packets.sort(key=lambda p: p.time)
OUT.parent.mkdir(exist_ok=True)
wrpcap(str(OUT), packets)
print(f"wrote {len(packets)} packets to {OUT}")
