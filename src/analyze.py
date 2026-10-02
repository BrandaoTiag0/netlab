"""
netlab - network traffic analyzer

Layers implemented:
  1. Most "talkative" IPs (highest packet count)
  2. Contacted domains (DNS queries)
  3. Port scan signals (one IP trying many different destination ports)
  4. Beaconing signals (regular connection intervals to the same destination),
     split by connection direction: outbound (possible C2) vs. inbound visits
  5. DNS tunneling signals (long, high-entropy subdomains under one base domain)

Usage: python src/analyze.py path/to/file.pcap [--home-net CIDR[,CIDR...]]
"""

import argparse
import math
import statistics
import ipaddress
from collections import Counter, defaultdict

from scapy.all import rdpcap, IP, TCP, DNS, DNSQR, DNSRR


def top_ips(packets, top_n=10):
    counts = Counter()
    for packet in packets:
        if IP in packet:
            counts[packet[IP].src] += 1
            counts[packet[IP].dst] += 1

    print(f"Top {top_n} most talkative IPs:")
    for ip, n in counts.most_common(top_n):
        print(f"  {ip:<20} {n} packets")


def contacted_domains(packets, top_n=15):
    domains = Counter()
    for packet in packets:
        if packet.haslayer(DNS) and packet.haslayer(DNSQR) and packet[DNS].qr == 0:  # qr=0 -> it's a query
            name = packet[DNSQR].qname.decode(errors="ignore").rstrip(".")
            domains[name] += 1

    print(f"\nContacted domains (top {top_n}):")
    if not domains:
        print("  (no DNS queries found)")
    for domain, n in domains.most_common(top_n):
        print(f"  {domain:<40} {n} requests")


def possible_port_scan(packets, port_threshold=15):
    """
    An IP INITIATING connections (pure SYN packets, no ACK) to many different
    destination ports is the classic port scan pattern.

    Note: we only count pure SYN (connection request), never SYN-ACK or ACK.
    Counting every TCP/UDP packet gave false positives: a DNS server replying
    to many clients on different ephemeral ports looked like "many different
    ports", but it was just replying, not trying to connect to anyone.
    """
    ports_by_source = defaultdict(set)

    for packet in packets:
        if IP in packet and TCP in packet:
            flags = packet[TCP].flags
            is_pure_syn = "S" in flags and "A" not in flags
            if is_pure_syn:
                source = packet[IP].src
                ports_by_source[source].add(packet[TCP].dport)

    suspects = {ip: ports for ip, ports in ports_by_source.items() if len(ports) >= port_threshold}

    print(f"\nPossible port scan (>= {port_threshold} distinct destination ports):")
    if not suspects:
        print("  (nothing found with this threshold)")
    for ip, ports in sorted(suspects.items(), key=lambda x: -len(x[1])):
        print(f"  {ip:<20} tried {len(ports)} different ports")


# Networks treated as "ours" when --home-net is not given: the RFC 1918
# private ranges, where client machines inside a company/home network live.
DEFAULT_HOME_NETS = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]


def parse_home_nets(text):
    """'203.161.44.208,10.0.0.0/8' -> list of ip_network. A bare IP becomes a /32."""
    return [ipaddress.ip_network(part.strip(), strict=False) for part in text.split(",") if part.strip()]


def in_home_net(ip, home_nets):
    """True if `ip` belongs to one of the home networks (i.e. it's "our" side of the capture)."""
    address = ipaddress.ip_address(ip)
    return any(address in net for net in home_nets)


def _connection_key(packet):
    """Same key for both directions of a TCP connection: the two (ip, port)
    endpoints in a fixed (sorted) order."""
    a = (packet[IP].src, packet[TCP].sport)
    b = (packet[IP].dst, packet[TCP].dport)
    return (a, b) if a <= b else (b, a)


def find_initiators(packets):
    """
    For each TCP connection, work out which side started it (the client) and
    which side accepted it (the server). Returns
    {connection_key: (client_endpoint, server_endpoint, method)}, where an
    endpoint is (ip, port) and method says which rule decided:

      1. "syn":    whoever sends the pure SYN (SYN without ACK) is the client.
      2. "synack": no SYN in the capture, but whoever sends the SYN-ACK is the
                   server.
      3. "port":   no handshake at all - the connection was already open when
                   the recording started (e.g. a RAT's kept-alive C2 channel).
                   Servers listen on fixed, usually lower ports (443, 80, 7007)
                   while clients use high ephemeral ports (49152+), so the
                   lower port is taken as the server. On a tie, whoever spoke
                   first is the client.
    """
    by_syn, by_synack, first_seen = {}, {}, {}

    for packet in packets:
        if IP not in packet or TCP not in packet:
            continue
        key = _connection_key(packet)
        src = (packet[IP].src, packet[TCP].sport)
        dst = (packet[IP].dst, packet[TCP].dport)
        flags = packet[TCP].flags

        if "S" in flags and "A" not in flags:
            by_syn.setdefault(key, (src, dst))      # sender of SYN = client
        elif "S" in flags and "A" in flags:
            by_synack.setdefault(key, (dst, src))   # sender of SYN-ACK = server
        first_seen.setdefault(key, (src, dst))

    initiators = {}
    for key, (src, dst) in first_seen.items():
        if key in by_syn:
            initiators[key] = (*by_syn[key], "syn")
        elif key in by_synack:
            initiators[key] = (*by_synack[key], "synack")
        elif dst[1] < src[1] or src[1] == dst[1]:
            initiators[key] = (src, dst, "port")
        else:
            initiators[key] = (dst, src, "port")
    return initiators


def connection_direction(client_ip, server_ip, home_nets):
    """
    outbound: one of our hosts connects out to the internet   (where C2 beaconing lives)
    inbound:  someone outside connects in to one of our hosts (scanners, visitors)
    internal: both sides are ours                             (file shares, domain controller)
    external: neither side is ours - the home network is probably wrong for this capture
    """
    client_home = in_home_net(client_ip, home_nets)
    server_home = in_home_net(server_ip, home_nets)
    if client_home and not server_home:
        return "outbound"
    if server_home and not client_home:
        return "inbound"
    if client_home and server_home:
        return "internal"
    return "external"


def possible_beaconing(packets, home_nets=None, min_events=10, min_avg_interval=5.0, top_n=5,
                       tolerance=0.25, min_regularity=0.6):
    """
    Beaconing: malware "phoning home" to a C2 server at very regular
    intervals (e.g. every 60s), because it's a program running on a timer,
    not a person clicking around. Human traffic is irregular.

    Direction matters. Regular traffic can be an infected host calling OUT
    to its C2 (what we want), but also an internet scanner calling IN to one
    of our servers on a schedule (not C2 at all). So every TCP connection is
    first given a client and a server (see find_initiators) and a direction
    relative to the home network (see connection_direction), and the results
    are split:
      - outbound (home client -> external server): flagged as possible beaconing
      - inbound (external client -> home server): listed separately, as
        regular visits - informational, usually scanners
      - internal / external: only in the informational ranking

    For each (client, server, server port) triplet we look at the packets
    the CLIENT sends that either carry a payload or are a SYN. Pure ACKs and
    other empty packets are ignored: malware can beacon by opening a new
    connection each time (SYN) or by sending periodic heartbeats inside a
    long-lived connection (payload). The server's replies are not counted,
    so they can't show up as a separate "pair".

    Packets less than 1s apart are collapsed into a single "event", so a
    burst of several packets from the same beacon doesn't get counted as
    several close-together events and fake a short interval.

    We then measure regularity around the median interval between events:
    the percentage of intervals within +/- `tolerance` (relative) of the
    median. A value close to 100% means nearly all intervals are the same ->
    regular -> suspicious. The median (rather than the mean) keeps a few
    long gaps, e.g. the host being offline, from hiding a real beacon.
    The coefficient of variation (CV = stdev / mean of the intervals) is
    also reported, as a secondary figure and as a tie-breaker when sorting.

    Parameters:
    - home_nets: list of ip_network that are "ours" (default: private ranges).
    - min_events: need enough events for the statistics to mean
      anything (with too few samples, everything looks "regular").
    - min_avg_interval: minimum median interval, in seconds. Ignores fast,
      bursty traffic (e.g. a page loading several resources in under a
      second) that isn't a beaconing pattern.
    - tolerance: how far from the median an interval can be, as a fraction
      of the median, and still count as "close".
    - min_regularity: minimum fraction of intervals that must be close to
      the median for a triplet to be listed as regular.
    - top_n: how many triplets to list in the informational ranking.
    """
    if home_nets is None:
        home_nets = DEFAULT_HOME_NETS

    initiators = find_initiators(packets)

    timestamps_by_triplet = defaultdict(list)
    for packet in packets:
        if IP in packet and TCP in packet:
            # Only packets with payload, or SYNs (new connections).
            payload_len = packet[IP].len - packet[IP].ihl * 4 - packet[TCP].dataofs * 4
            if payload_len == 0 and "S" not in packet[TCP].flags:
                continue
            client, server, _ = initiators[_connection_key(packet)]
            # Only what the client sends; server replies are skipped.
            if (packet[IP].src, packet[TCP].sport) != client:
                continue
            key = (client[0], server[0], server[1])
            timestamps_by_triplet[key].append(float(packet.time))

    qualifying = []  # (key, direction, event_count, median_interval, cv, regularity)

    for key, times in timestamps_by_triplet.items():
        times.sort()

        # Collapse packets less than 1s apart into a single event.
        deduped = [times[0]]
        for t in times[1:]:
            if t - deduped[-1] >= 1.0:
                deduped.append(t)

        if len(deduped) < min_events:
            continue

        intervals = [deduped[i] - deduped[i - 1] for i in range(1, len(deduped))]
        median_interval = statistics.median(intervals)
        if median_interval < min_avg_interval:
            continue

        cv = statistics.stdev(intervals) / statistics.mean(intervals)
        close = [x for x in intervals if abs(x - median_interval) <= tolerance * median_interval]
        regularity = len(close) / len(intervals)
        direction = connection_direction(key[0], key[1], home_nets)
        qualifying.append((key, direction, len(deduped), median_interval, cv, regularity))

    def by_regularity(r):
        return (-r[5], r[4])

    def print_row(row, show_direction=False):
        (client_ip, server_ip, port), direction, n, median_interval, cv, regularity = row
        suffix = f"  [{direction}]" if show_direction else ""
        print(f"  {client_ip:<15} -> {server_ip:<15}:{port:<6} {n} events, "
              f"median interval {median_interval:.1f}s, regularity {regularity:.0%}, CV {cv:.2f}{suffix}")

    # --- Context: which side is "ours", and how connections split by direction.
    directions = Counter(connection_direction(c[0], s[0], home_nets) for c, s, _ in initiators.values())
    methods = Counter(method for _, _, method in initiators.values())
    print(f"\nHome network: {', '.join(str(n) for n in home_nets)}")
    print(f"TCP connections: {directions['outbound']} outbound, {directions['inbound']} inbound, "
          f"{directions['internal']} internal, {directions['external']} external "
          f"(client found by SYN: {methods['syn']}, by SYN-ACK: {methods['synack']}, by port: {methods['port']})")

    all_ips = Counter()
    for packet in packets:
        if IP in packet:
            all_ips[packet[IP].src] += 1
            all_ips[packet[IP].dst] += 1
    if all_ips and not any(in_home_net(ip, home_nets) for ip in all_ips):
        busiest = all_ips.most_common(1)[0][0]
        print(f"  WARNING: no host in this capture is in the home network, so no connection can be "
              f"outbound or inbound. The most talkative IP is {busiest} - if that's the machine "
              f"being monitored, re-run with --home-net {busiest}")

    criteria = (f">= {min_events} events, median interval >= {min_avg_interval}s, "
                f"regularity >= {min_regularity:.0%} of intervals within +/-{tolerance:.0%} of the median")
    regular = [r for r in qualifying if r[5] >= min_regularity]

    print(f"\nPossible beaconing - outbound, home host -> external server ({criteria}):")
    outbound = sorted((r for r in regular if r[1] == "outbound"), key=by_regularity)
    if not outbound:
        print("  (nothing found with these parameters)")
    for row in outbound:
        print_row(row)

    print("\nRegular inbound visits - external client -> home server "
          "(same criteria; informational, usually scanners, not C2):")
    inbound = sorted((r for r in regular if r[1] == "inbound"), key=by_regularity)
    if not inbound:
        print("  (nothing found with these parameters)")
    for row in inbound:
        print_row(row)

    print(f"\nTop {top_n} most regular triplets, any direction (informational):")
    if not qualifying:
        print("  (not enough qualifying events)")
    for row in sorted(qualifying, key=by_regularity)[:top_n]:
        print_row(row, show_direction=True)


def _shannon_entropy(s):
    """Bits of entropy per character. Real words/hostnames score low
    (repeated letters, limited alphabet); random/base32/base64-looking
    strings score high (close to log2(alphabet size))."""
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def possible_dns_tunneling(packets, min_queries=20, min_avg_label_length=30, min_entropy=4.0, top_n=10):
    """
    DNS tunneling hides data - or a whole C2 channel - inside DNS queries,
    usually as a long, random-looking subdomain of a domain the attacker
    controls, e.g. "dGhpcyBpcyBhIHNlY3JldA.evil.com" instead of
    "www.evil.com". Two signals catch this:
      - the subdomain is long (real hostnames are rarely 40+ characters)
      - the subdomain looks random: high Shannon entropy, unlike real
        words or hostnames, which repeat common letters and patterns

    We group queries by "base domain" (the last two labels - "evil.com"
    out of "xyz.evil.com") and flag a base domain once it has enough
    queries, a high average subdomain length, AND high average entropy.
    Requiring all three keeps us from flagging domains that are merely
    long (some legitimate CDN/tracking hostnames are) but not random.
    """
    subdomains_by_base = defaultdict(list)

    for packet in packets:
        if packet.haslayer(DNS) and packet.haslayer(DNSQR) and packet[DNS].qr == 0:
            name = packet[DNSQR].qname.decode(errors="ignore").rstrip(".")
            labels = name.split(".")
            if len(labels) <= 2:
                continue  # no subdomain to analyze, just "domain.tld"
            base_domain = ".".join(labels[-2:])
            subdomain = ".".join(labels[:-2])
            subdomains_by_base[base_domain].append(subdomain)

    results = []  # (base_domain, query_count, avg_length, avg_entropy, unique_ratio)

    for base_domain, subdomains in subdomains_by_base.items():
        if len(subdomains) < min_queries:
            continue
        avg_length = statistics.mean(len(s) for s in subdomains)
        avg_entropy = statistics.mean(_shannon_entropy(s) for s in subdomains)
        unique_ratio = len(set(subdomains)) / len(subdomains)
        results.append((base_domain, len(subdomains), avg_length, avg_entropy, unique_ratio))

    suspicious = [r for r in results if r[2] >= min_avg_label_length and r[3] >= min_entropy]

    print(f"\nPossible DNS tunneling (>= {min_queries} queries, "
          f"avg subdomain length >= {min_avg_label_length}, avg entropy >= {min_entropy} bits/char):")
    if not suspicious:
        print("  (nothing found with these parameters)")
    for base_domain, n, avg_length, avg_entropy, unique_ratio in sorted(suspicious, key=lambda r: -r[3]):
        print(f"  {base_domain:<30} {n} queries, avg length {avg_length:.1f}, "
              f"avg entropy {avg_entropy:.2f} bits/char, {unique_ratio:.0%} unique")

    print(f"\nTop {top_n} base domains by subdomain query volume (informational):")
    if not results:
        print("  (no domains with subdomains found)")
    for base_domain, n, avg_length, avg_entropy, unique_ratio in sorted(results, key=lambda r: -r[1])[:top_n]:
        print(f"  {base_domain:<30} {n} queries, avg length {avg_length:.1f}, "
              f"avg entropy {avg_entropy:.2f} bits/char")


def ip_without_dns(packets):
    """
    Malware often connects straight to a hard-coded IP, with no DNS lookup
    beforehand, whereas normal software resolves a name first. We walk the
    packets in order, remember every IP that appeared in a DNS A-record answer,
    and flag each pure SYN (flags == "S") to a public IP that has not been
    resolved yet. SYNs are counted per (src, dst, dport).
    """
    counts = Counter()
    for packet in packets:
        if IP in packet:
            counts[packet[IP].src] += 1
            counts[packet[IP].dst] += 1
    local_host = counts.most_common(1)[0][0] if counts else None

    resolved = set()
    syns = Counter()
    inbound_ignored = 0

    for packet in packets:
        if DNS in packet and packet[DNS].qr == 1:
            dns = packet[DNS]
            for rr in dns.an or []:
                if isinstance(rr, DNSRR) and rr.type == 1:
                    resolved.add(rr.rdata)
        elif IP in packet and TCP in packet and packet[TCP].flags == "S":
            if packet[IP].src != local_host:
                inbound_ignored += 1
                continue
            dst = packet[IP].dst
            if ipaddress.ip_address(dst).is_global and dst not in resolved:
                syns[(packet[IP].src, dst, packet[TCP].dport)] += 1

    print("\nConnections to IPs without prior DNS:")
    if not syns:
        print("  (nothing found)")
    for (src, dst, dport), n in syns.most_common():
        unusual = "  [unusual port]" if dport not in (80, 443) else ""
        print(f"  {src:<15} -> {dst}:{dport}  {n} SYNs{unusual}")
    print(f"  ({inbound_ignored} inbound SYNs ignored; local host = {local_host})")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="netlab - network traffic analyzer")
    parser.add_argument("pcap", help="path to a .pcap file")
    parser.add_argument("--home-net", type=parse_home_nets, default=DEFAULT_HOME_NETS,
                        help="comma-separated networks/IPs that are 'ours', e.g. 203.161.44.208 or "
                             "10.0.0.0/8,203.161.44.208/32 (replaces the default: the private ranges "
                             "10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)")
    args = parser.parse_args()

    packets = rdpcap(args.pcap)
    print(f"Total packets: {len(packets)}\n")

    top_ips(packets)
    contacted_domains(packets)
    possible_port_scan(packets)
    possible_beaconing(packets, home_nets=args.home_net)
    possible_dns_tunneling(packets)
    ip_without_dns(packets)
