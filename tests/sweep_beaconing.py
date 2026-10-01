"""Temporary script: sweep (tolerance, min_regularity) over every capture."""
import contextlib
import io
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from scapy.all import rdpcap  # noqa: E402

from analyze import possible_beaconing  # noqa: E402

COMBOS = [(0.10, 0.5), (0.15, 0.5), (0.20, 0.5), (0.25, 0.5), (0.25, 0.6), (0.30, 0.6)]
LINE = re.compile(r"^\s+(\S+)\s+-> (\S+)\s*:(\d+)\s")

captures = {p.name: rdpcap(str(p)) for p in sorted((ROOT / "captures").glob("*.pcap"))}


def flagged(packets, tolerance, min_regularity):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        possible_beaconing(packets, tolerance=tolerance, min_regularity=min_regularity)
    lines = buf.getvalue().splitlines()
    start = next(i for i, l in enumerate(lines) if l.startswith("Possible beaconing"))
    end = next((i for i in range(start + 1, len(lines)) if not lines[i].strip()), len(lines))
    return [f"{m[1]} -> {m[2]}:{m[3]}" for l in lines[start + 1:end] if (m := LINE.match(l))]


for tol, reg in COMBOS:
    print(f"\n=== tolerance={tol:.2f}, min_regularity={reg:.0%} ===")
    print(f"{'capture':<50} {'flagged':>7}  destinations")
    for name, packets in captures.items():
        hits = flagged(packets, tol, reg)
        print(f"{name:<50} {len(hits):>7}  {', '.join(hits) if hits else '-'}")
        if name == "jitter.pcap":
            got = {h.split(" -> ")[1].split(":")[0] for h in hits}
            marks = ", ".join(f".{n}={'yes' if f'93.184.216.{n}' in got else 'no'}" for n in range(35, 40))
            print(f"{'':<50} {'':>7}  jitter 0/10/20/30/50%: {marks}")
