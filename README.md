# netlab

A Python network traffic analyzer. Give it a `.pcap` file and it tells you what happened: which machines talked to which, what domains were contacted, and signs of suspicious activity (port scan, DNS tunneling, beaconing).

Fed with real malware infection captures (source: [malware-traffic-analysis.net](https://www.malware-traffic-analysis.net/)).

## Current status

- [x] Read a `.pcap` and list the top 10 most-talkative IPs
- [x] List contacted domains (DNS)
- [x] Port scan detector
- [x] Beaconing detector (coefficient of variation of packet intervals)
- [x] DNS tunneling detector (subdomain length + Shannon entropy)

## Usage

```bash
py -m pip install -r requirements.txt
py src/analyze.py captures/example.pcap
```

Put downloaded `.pcap` files in `captures/` (gitignored - see `.gitignore`).

## Analyses

### 2026-02-28 - "Easy As 123" (NetSupport Manager RAT)
Source: [malware-traffic-analysis.net, 2026-02-28](https://www.malware-traffic-analysis.net/2026/02/28/index.html)

- Infected host: `10.2.28.88` (most talkative in the capture, 14673 packets)
- Malicious IP confirmed by the exercise: `45.131.214.85` - shows up in the top IPs list (550 packets), consistent with the NetSupport RAT's C2
- DNS domains reveal the environment: `wpad.easyas123.tech` and the LDAP lookup on `easyas123.tech` show the company's Windows domain; the rest is normal Windows/Office traffic (Microsoft, MSN, Bing)
- Port scan: nothing found - correct, this exercise isn't about scanning

**Bug/lesson - port scan false positive:** the first version of the port scan detector counted every TCP/UDP packet, and flagged the DNS server (`10.2.28.2`) as "suspicious" (379 different ports) - but that was just it REPLYING to client requests on ephemeral ports, not trying to connect to anyone. Fixed by only counting pure SYN packets (a real connection request, no ACK). A good lesson in how a naive detector produces false positives.

**Bug/lesson - beaconing blind spot:** the first version of the beaconing detector also borrowed the "pure SYN only" filter from the port scan detector, assuming the same logic would apply. It didn't: the RAT opened a single TCP connection to `45.131.214.85:443` and sent its heartbeat inside that one connection (only 1 pure SYN packet in the whole capture, vs. 275 other packets on the same connection). A SYN-only detector is blind to malware that beacons over a kept-alive connection instead of reconnecting every time. Fixed by measuring intervals between *all* packets on each (source, destination, port) triplet, not just SYNs - the SYN filter solved a problem specific to port scanning that doesn't exist here.

**Beaconing confirmed:** with that fix, the detector catches `10.2.28.88 <-> 45.131.214.85:443` with textbook precision - 261 events, average interval 60.1s, CV 0.00. That's the NetSupport RAT's C2 "phoning home" on an almost perfectly constant rhythm. It independently confirms what the exercise already stated about this IP being malicious, but now there's a number (near-zero CV) that proves it statistically rather than "because the site said so".

**Bonus finding - a reminder that regularity isn't proof of malice:** the detector also flagged `104.208.203.89` (a Microsoft/Azure-range IP) with similarly regular intervals (CV 0.06-0.23, every ~4 minutes). This is very likely legitimate background telemetry or update-check traffic, not malware. Statistical regularity narrows down what to look at - it doesn't replace checking who the destination actually is.

**DNS tunneling detector - tuning lesson:** this exercise has no actual tunneling, so the detector was first validated against synthetic data: random 45-character subdomains under a fake C2 domain (the tunneling case) alongside long, CDN-style hostnames like `cdn-edge-server-cluster-N.contentdelivery.example.com` under a normal domain (a deliberately tricky "legit but long" case). A first pass with `min_entropy=3.5` flagged *both* as suspicious - the CDN-style names are verbose, not random, but 3.5 bits/char wasn't a high enough bar to tell the difference (entropy 3.81). Raising the threshold to `4.0` fixed it: the CDN-style domain now only shows up in the informational top-10 (not flagged), while the real tunneling case stays flagged (entropy 4.51). Run against the NetSupport RAT capture itself: nothing flagged - correctly, since there's no tunneling here - and the real domains involved (microsoft.com, easyas123.tech, mshome.net, msn.com, microsoftonline.com) all score low entropy (1.58-2.80 bits/char), consistent with ordinary traffic. A useful reminder that a detector needs to be tested against both a true positive and a tricky near-miss, not just real-world "nothing happens" data.
