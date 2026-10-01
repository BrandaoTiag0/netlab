"""Generate captures/synthetic.pcap with known malicious-looking patterns.

1. Port scan: internal host -> 30 distinct TCP ports on one IP.
2. DNS tunneling: 50 queries for random 40-char subdomains of one domain.
3. Beaconing: host -> external IP:7007 every 10s +-10%, 20 times, no prior DNS.
"""
import random
import string
from pathlib import Path

from scapy.all import DNS, DNSQR, IP, TCP, UDP, Ether, wrpcap

random.seed(1337)

OUT = Path(__file__).resolve().parent.parent / "captures" / "synthetic.pcap"

packets = []


def add(pkt, t):
    pkt.time = t
    packets.append(pkt)


t0 = 1_700_000_000.0

# (1) port scan
scanner, target = "192.168.1.10", "192.168.1.50"
ports = random.sample(range(1, 10000), 30)
for i, port in enumerate(ports):
    t = t0 + i * 0.05
    add(Ether() / IP(src=scanner, dst=target) / TCP(sport=40000 + i, dport=port, flags="S"), t)
    add(Ether() / IP(src=target, dst=scanner) / TCP(sport=port, dport=40000 + i, flags="RA"), t + 0.001)

# (2) DNS tunneling
client, resolver, domain = "192.168.1.20", "192.168.1.1", "tunnel.example.com"
alphabet = string.ascii_lowercase + string.digits
for i in range(50):
    t = t0 + 10 + i * 0.5
    label = "".join(random.choices(alphabet, k=40))
    q = f"{label}.{domain}."
    add(Ether() / IP(src=client, dst=resolver) / UDP(sport=50000 + i, dport=53)
        / DNS(id=i, rd=1, qd=DNSQR(qname=q)), t)

# (3) beaconing, no DNS beforehand
victim, c2 = "192.168.1.30", "93.184.216.34"
t = t0 + 100
for i in range(20):
    sport = 51000 + i
    add(Ether() / IP(src=victim, dst=c2) / TCP(sport=sport, dport=7007, flags="S", seq=1000), t)
    add(Ether() / IP(src=c2, dst=victim) / TCP(sport=7007, dport=sport, flags="SA", seq=2000, ack=1001), t + 0.02)
    add(Ether() / IP(src=victim, dst=c2) / TCP(sport=sport, dport=7007, flags="A", seq=1001, ack=2001), t + 0.021)
    add(Ether() / IP(src=victim, dst=c2) / TCP(sport=sport, dport=7007, flags="PA", seq=1001, ack=2001) / b"ping", t + 0.022)
    t += 10 * random.uniform(0.9, 1.1)

packets.sort(key=lambda p: p.time)
OUT.parent.mkdir(exist_ok=True)
wrpcap(str(OUT), packets)
print(f"wrote {len(packets)} packets to {OUT}")
