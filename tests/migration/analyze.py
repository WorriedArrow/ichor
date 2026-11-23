#!/usr/bin/env python3
"""Reads a migration campaign's logs (campaign.sh) and says, run by run,
what the guest saw and what broke: the maintenance notice's lead, the
blackout (the guest's tick gap, the clock's jump, the TCP stream's gap),
iperf3's dip, the disk hammer's errors and slow reads, gVNIC resets, and
whether the API still ran a container afterwards. Then a summary.

Guest times are the guest's wall clock corrected by its last NTP sample
(true = wall + offset), which puts them on the peer's (chrony-synced) clock.

Usage: analyze.py OUT_DIR [--json]"""
import json
import re
import statistics
import sys
from pathlib import Path

out = Path(sys.argv[1])


def lines(name):
    p = out / name
    if not p.exists():
        return []
    rows = []
    for l in p.read_text(errors="replace").splitlines():
        t, _, rest = l.partition(" ")
        try:
            rows.append((float(t), rest))
        except ValueError:
            pass
    return rows


STAMP = re.compile(r"uptime ([\d.]+) s, wall ([\d.]+)")
CLOCK = re.compile(r"clock ([+-][\d.]+) ms from the metadata server's NTP \(rtt ([\d.]+) ms")
STEERING = re.compile(r"steering ([+-][\d.]+) ppm")
STEPPED = re.compile(r"clock stepped ([+-][\d.]+) ms")
NOTICE = re.compile(r"maintenance-event (\S+)")
GAP = re.compile(r"no tick for (\d+) ms")
HAMMER_SUM = re.compile(r"hammer: (\d+) reads \(([\d.]+) MiB/s\), (\d+) errors, slowest (\d+) ms")
IPERF = re.compile(r"\]\s+[\d.]+-[\d.]+\s+sec\s+[\d.]+ \w?Bytes\s+([\d.]+) (\w?)bits/sec")
BAD = re.compile(r"panic|FAILED|fatal|page fault in the kernel|double fault", re.I)

# The guest's log, in its own clock and in true time.
serial = []
offset_ms = 0.0
clock_samples = []
for peer_t, text in lines("serial.log"):
    m = STAMP.search(text)
    wall = float(m.group(2)) if m else None
    c = CLOCK.search(text)
    # (An answer that waited for an idle uplink's 10 ms poll is skewed by
    # half that wait: only quick round trips are taken.)
    if c and wall and float(c.group(2)) < 3.0:
        offset_ms = float(c.group(1))
        s = STEERING.search(text)
        steer = float(s.group(1)) if s else None
        clock_samples.append((wall + offset_ms / 1000, offset_ms, float(c.group(2)), steer))
    true = wall + offset_ms / 1000 if wall else peer_t
    serial.append((true, text, wall))

runs = {}
for t, text in lines("runs.log"):
    m = re.match(r"RUN (\d+) (request|done)(?: rc=(\d+))?", text)
    if m:
        runs.setdefault(int(m.group(1)), {})[m.group(2)] = t
        if m.group(3) is not None:
            runs[int(m.group(1))]["rc"] = int(m.group(3))
runs = {i: r for i, r in runs.items() if "request" in r and "done" in r}


def window(rows, a, b):
    return [r for r in rows if a <= r[0] <= b]


def iperf_rates():
    rates = []
    for t, text in lines("load-iperf.log"):
        m = IPERF.search(text)
        if m and "sender" not in text and "receiver" not in text:
            scale = {"": 1e-6, "K": 1e-3, "M": 1, "G": 1e3}.get(m.group(2), 1)
            rates.append((t, float(m.group(1)) * scale))
    return rates


rates = iperf_rates()
tcp = lines("tcp-recv.log")
loads = {n: lines(f"load-{n}.log") for n in ("iperf", "tcp", "fio", "cpu")}

results = []
ordered = sorted(runs)
for k, i in enumerate(ordered):
    r = runs[i]
    a = r["request"]
    nxt = runs[ordered[k + 1]]["request"] if k + 1 < len(ordered) else r["done"] + 300
    b = min(r["done"] + 180, nxt)
    ev = window(serial, a - 5, b)
    # (GCP's simulate call fails now and then, BACKEND_ERROR, and then
    # nothing migrates: such a run tests nothing.)
    res = {"run": i, "gcloud_s": round(r["done"] - a, 1), "rc": r.get("rc", "-")}
    notices = [(t, NOTICE.search(x).group(1)) for t, x, _ in ev if NOTICE.search(x)]
    migrate = [t for t, v in notices if v != "NONE"]
    res["notice"] = bool(migrate)
    gaps = [(t, int(GAP.search(x).group(1))) for t, x, _ in ev if GAP.search(x)]
    res["tick_gap_ms"] = max((g for _, g in gaps), default=0)
    blackout_start = None
    if gaps:
        t_end, g = max(gaps, key=lambda x: x[1])
        blackout_start = t_end - g / 1000
    # The clock: the last sample before the request, the first well after.
    before = [s for s in clock_samples if s[0] < a]
    after = [s for s in clock_samples if s[0] > r["done"] + 20]
    if before and after:
        res["clock_before_ms"] = round(before[-1][1], 3)
        res["clock_after_ms"] = round(after[0][1], 3)
        res["clock_jump_ms"] = round(after[0][1] - before[-1][1], 3)
    # With the wall clock disciplined, a jump shows as the worst offset
    # around the migration (or a step), and a new host's TSC rate as a
    # change in the learned steering rate.
    near = [s for s in clock_samples if a <= s[0] <= r["done"] + 60]
    if near:
        res["clock_worst_ms"] = round(max((s[1] for s in near), key=abs), 3)
    res["clock_steps"] = [x for _, x, _ in ev if STEPPED.search(x)][:3]
    rate_before = [s[3] for s in before if s[3] is not None]
    rate_after = [s[3] for s in clock_samples if s[0] > r["done"] + 120 and s[0] <= b and s[3] is not None]
    if rate_before and rate_after:
        res["rate_change_ppm"] = round(rate_after[-1] - rate_before[-1], 3)
    # The TCP stream from a cell: its longest silence, and whether it broke.
    stream = window(tcp, a, b)
    res["tcp_gap_s"] = round(max((y[0] - x[0] for x, y in zip(stream, stream[1:])), default=0), 2)
    res["tcp_broke"] = any("CLOSED" in x for _, x in stream) or any(
        x.startswith("EXIT") for _, x in window(loads["tcp"], a, b)
    )
    if blackout_start is None and stream:
        silent = max(zip(stream, stream[1:]), key=lambda p: p[1][0] - p[0][0], default=None)
        if silent and silent[1][0] - silent[0][0] > 1:
            blackout_start = silent[0][0]
    if migrate and blackout_start:
        res["notice_lead_s"] = round(blackout_start - migrate[0], 1)
    # iperf3: its rate before, its lowest after, the seconds it was nearly
    # stopped, and whether it broke off.
    base = [v for t, v in rates if a - 60 <= t < a]
    during = [v for t, v in rates if a <= t <= b]
    if base:
        med = statistics.median(base)
        res["iperf_base_mbps"] = round(med, 1)
        res["iperf_min_mbps"] = round(min(during), 1) if during else 0
        res["iperf_stalled_s"] = sum(1 for v in during if v < med * 0.1)
    res["iperf_broke"] = any(x.startswith("EXIT") for _, x in window(loads["iperf"], a, b))
    # The disk, gVNIC, and anything fatal.
    res["disk_errors"] = sum(int(HAMMER_SUM.search(x).group(3)) for _, x, _ in ev if HAMMER_SUM.search(x))
    res["disk_slowest_ms"] = max((int(HAMMER_SUM.search(x).group(4)) for _, x, _ in ev if HAMMER_SUM.search(x)), default=0)
    res["disk_lines"] = [x for _, x, _ in ev if "hammer:" in x and ("failed" in x or "took" in x)][:5]
    res["gve"] = [x for _, x, _ in ev if "gve:" in x][:5]
    res["bad"] = [x for _, x, _ in ev if BAD.search(x)][:5]
    health = (out / f"health-{i}.log").read_text(errors="replace") if (out / f"health-{i}.log").exists() else ""
    res["api_ok"] = "alive" in health
    res["internet_ok"] = "internet" in health
    results.append(res)

if "--json" in sys.argv:
    print(json.dumps(results, indent=1))
    sys.exit(0)

print(f"{len(results)} runs\n")
cols = ["run", "gcloud_s", "rc", "notice", "notice_lead_s", "tick_gap_ms", "clock_jump_ms", "clock_worst_ms",
        "rate_change_ppm", "tcp_gap_s",
        "tcp_broke", "iperf_base_mbps", "iperf_min_mbps", "iperf_stalled_s", "iperf_broke",
        "disk_errors", "disk_slowest_ms", "api_ok", "internet_ok"]
print("\t".join(cols))
for r in results:
    print("\t".join(str(r.get(c, "-")) for c in cols))
    for key in ("gve", "disk_lines", "bad", "clock_steps"):
        for x in r[key]:
            print(f"    {key}: {x}")


def col(c):
    return [r[c] for r in results if isinstance(r.get(c), (int, float)) and not isinstance(r.get(c), bool)]


def stat(c):
    v = col(c)
    return f"min {min(v)} / median {statistics.median(v)} / max {max(v)}" if v else "none"


print("\nsummary")
failed = [r["run"] for r in results if r["rc"] not in (0, "-")]
print(f"  GCP's simulate call failed in runs {failed or 'none'}; a run with no notice may not have migrated")
print(f"  notice seen before the blackout: {sum(1 for r in results if r['notice'])}/{len(results)}; lead (s): {stat('notice_lead_s')}")
print(f"  guest tick gap (ms): {stat('tick_gap_ms')}")
print(f"  clock jump per run (ms): {stat('clock_jump_ms')}; worst offset around a migration (ms): {stat('clock_worst_ms')}")
print(f"  steps after the first: {sum(len(r['clock_steps']) for r in results)}; host TSC rate change per migration (ppm): {stat('rate_change_ppm')}")
# (Fifteen minutes after the clock was last stepped: a new boot steps it.)
step_times = [t for t, x, _ in serial if STEPPED.search(x)] or [clock_samples[0][0] if clock_samples else 0]
settled = [s[1] for s in clock_samples if s[0] > max((t for t in step_times if t <= s[0]), default=s[0]) + 900]
if settled:
    print(f"  offset from NTP after the first 15 minutes (ms): worst {max(settled, key=abs):.3f}, median |offset| {statistics.median(abs(x) for x in settled):.3f}")
print(f"  TCP stream gap (s): {stat('tcp_gap_s')}; broke in {sum(r['tcp_broke'] for r in results)} runs")
print(f"  iperf3 stalled (s): {stat('iperf_stalled_s')}; broke in {sum(r['iperf_broke'] for r in results)} runs")
print(f"  disk errors: {sum(r['disk_errors'] for r in results)}; slowest read (ms): {stat('disk_slowest_ms')}")
print(f"  gVNIC events in {sum(1 for r in results if r['gve'])} runs; fatal lines in {sum(1 for r in results if r['bad'])} runs")
print(f"  API ran a container after: {sum(r['api_ok'] for r in results)}/{len(results)}; internet: {sum(r['internet_ok'] for r in results)}/{len(results)}")
if clock_samples:
    print(f"  clock offset over the campaign: first {clock_samples[0][1]:.3f} ms, last {clock_samples[-1][1]:.3f} ms")
