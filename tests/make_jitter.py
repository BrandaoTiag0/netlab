"""Generate captures/jitter.pcap: 5 beacons with increasing jitter.

One internal host (192.168.1.30) beacons to 5 different public IPs on port
7007, 30 connections each, base interval 30s. Each beacon has a different
jitter (interval uniform in base*(1-j) .. base*(1+j)): 0%, 10%, 20%, 30%, 50%.
"""
import random
from pathlib import Path

from scapy.all import IP, TCP, Ether, wrpcap

random.seed(1337)

OUT = Path(__file__).resolve().parent.parent / "captures" / "jitter.pcap"

packets = []


def add(pkt, t):
    pkt.time = t
    packets.append(pkt)


t0 = 1_700_000_000.0
victim = "192.168.1.30"
base = 30.0
beacons = [("93.184.216.35", 0.0), ("93.184.216.36", 0.1), ("93.184.216.37", 0.2),
           ("93.184.216.38", 0.3), ("93.184.216.39", 0.5)]

for n, (c2, jitter) in enumerate(beacons):
    t = t0 + n * 0.5
    for i in range(30):
        sport = 40000 + n * 100 + i
        add(Ether() / IP(src=victim, dst=c2) / TCP(sport=sport, dport=7007, flags="S", seq=1000), t)
        add(Ether() / IP(src=c2, dst=victim) / TCP(sport=7007, dport=sport, flags="SA", seq=2000, ack=1001), t + 0.02)
        add(Ether() / IP(src=victim, dst=c2) / TCP(sport=sport, dport=7007, flags="A", seq=1001, ack=2001), t + 0.021)
        add(Ether() / IP(src=victim, dst=c2) / TCP(sport=sport, dport=7007, flags="PA", seq=1001, ack=2001) / b"ping", t + 0.022)
        t += base * random.uniform(1 - jitter, 1 + jitter)

packets.sort(key=lambda p: p.time)
OUT.parent.mkdir(exist_ok=True)
wrpcap(str(OUT), packets)
print(f"wrote {len(packets)} packets to {OUT}")
