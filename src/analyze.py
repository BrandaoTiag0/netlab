"""
netlab - network traffic analyzer

Layers implemented:
  1. Most "talkative" IPs (highest packet count)
  2. Contacted domains (DNS queries)
  3. Port scan signals (one IP trying many different destination ports)
  4. Beaconing signals (regular connection intervals to the same destination)
  5. DNS tunneling signals (long, high-entropy subdomains under one base domain)

Usage: python src/analyze.py path/to/file.pcap
"""

import math
import statistics
import sys
import ipaddress
from collections import Counter, defaultdict

from scapy.all import rdpcap, IP, TCP, DNS, DNSQR


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


def possible_beaconing(packets, min_events=10, min_avg_interval=5.0, top_n=5, tolerance=0.25, min_regularity=0.6):
    """
    Beaconing: malware "phoning home" to a C2 server at very regular
    intervals (e.g. every 60s), because it's a program running on a timer,
    not a person clicking around. Human traffic is irregular.

    For each (source, destination, destination port) triplet we look at TCP
    packets that either carry a payload or are a SYN, and whose destination
    is a global IP address (is_global). Pure ACKs and other empty packets
    are ignored: malware can beacon by opening a new connection each time
    (SYN) or by sending periodic heartbeats inside a long-lived connection
    (payload).

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

    Filters, to avoid noise:
    - min_events: need enough events for the statistics to mean
      anything (with too few samples, everything looks "regular").
    - min_avg_interval: minimum median interval, in seconds. Ignores fast,
      bursty traffic (e.g. a page loading several resources in under a
      second) that isn't a beaconing pattern.
    - tolerance: how far from the median an interval can be, as a fraction
      of the median, and still count as "close".
    - min_regularity: minimum fraction of intervals that must be close to
      the median for the destination to be flagged as suspicious.
    - top_n: how many destinations to list in the informational ranking.
    """
    timestamps_by_triplet = defaultdict(list)
    for packet in packets:
        if IP in packet and TCP in packet:
            # Only packets with payload, or SYNs (new connections).
            payload_len = packet[IP].len - packet[IP].ihl * 4 - packet[TCP].dataofs * 4
            if payload_len == 0 and "S" not in packet[TCP].flags:
                continue
            # Only traffic to globally routable destinations.
            if not ipaddress.ip_address(packet[IP].dst).is_global:
                continue
            key = (packet[IP].src, packet[IP].dst, packet[TCP].dport)
            timestamps_by_triplet[key].append(float(packet.time))

    qualifying = []  # (key, event_count, median_interval, cv, regularity)

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
        qualifying.append((key, len(deduped), median_interval, cv, regularity))

    suspicious = [r for r in qualifying if r[4] >= min_regularity]

    print(f"\nPossible beaconing (>= {min_events} events, "
          f"median interval >= {min_avg_interval}s, "
          f"regularity >= {min_regularity:.0%} of intervals within +/-{tolerance:.0%} of the median):")
    if not suspicious:
        print("  (nothing found with these parameters)")
    for (src, dst, port), n, median_interval, cv, regularity in sorted(suspicious, key=lambda r: (-r[4], r[3])):
        print(f"  {src:<15} -> {dst:<15}:{port:<6} {n} events, "
              f"median interval {median_interval:.1f}s, regularity {regularity:.0%}, CV {cv:.2f}")

    print(f"\nTop {top_n} most regular destinations (highest regularity, informational):")
    if not qualifying:
        print("  (not enough qualifying events)")
    else:
        for (src, dst, port), n, median_interval, cv, regularity in sorted(qualifying, key=lambda r: (-r[4], r[3]))[:top_n]:
            print(f"  {src:<15} -> {dst:<15}:{port:<6} {n} events, "
                  f"median interval {median_interval:.1f}s, regularity {regularity:.0%}, CV {cv:.2f}")


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


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python src/analyze.py path/to/file.pcap")
        sys.exit(1)

    packets = rdpcap(sys.argv[1])
    print(f"Total packets: {len(packets)}\n")

    top_ips(packets)
    contacted_domains(packets)
    possible_port_scan(packets)
    possible_beaconing(packets)
    possible_dns_tunneling(packets)
