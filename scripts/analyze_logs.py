#!/usr/bin/env python3
"""Offline JSONL log analyzer for fatext-server (access, events, metrics).

Produces per-route p50/p95/p99/max latency & stage breakdowns, error hotspots,
SSE disconnect reasons, DM/room/mail throughput summaries, and optimization hints.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter, defaultdict
from pathlib import Path


def percentile(sorted_vals: list[float], p: float) -> float:
    if not sorted_vals:
        return 0.0
    if len(sorted_vals) == 1:
        return float(sorted_vals[0])
    idx = (len(sorted_vals) - 1) * (p / 100.0)
    lo = int(idx)
    hi = min(lo + 1, len(sorted_vals) - 1)
    frac = idx - lo
    return sorted_vals[lo] * (1.0 - frac) + sorted_vals[hi] * frac


def iter_jsonl(log_dir: Path, prefix: str, date_filter: str | None) -> list[dict]:
    records: list[dict] = []
    if date_filter:
        paths = [log_dir / f"{prefix}-{date_filter}.jsonl"]
    else:
        paths = sorted(log_dir.glob(f"{prefix}-*.jsonl"))
    for p in paths:
        if not p.is_file():
            continue
        for raw in p.read_text(encoding="utf-8", errors="replace").splitlines():
            line = raw.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return records


def analyze(log_dir: Path, date_filter: str | None, top_n: int) -> dict:
    access = iter_jsonl(log_dir, "access", date_filter)
    events = iter_jsonl(log_dir, "events", date_filter)
    metrics = iter_jsonl(log_dir, "metrics", date_filter)

    by_route: dict[str, list[dict]] = defaultdict(list)
    err_codes: Counter[str] = Counter()
    slow_reqs: list[dict] = []
    total_reqs = len(access)
    err_reqs = 0
    rate_limited = 0

    for rec in access:
        key = f"{rec.get('method', '?')} {rec.get('route', '?')}"
        by_route[key].append(rec)
        st = int(rec.get("status", 0))
        if st >= 400:
            err_reqs += 1
            ec = rec.get("err_code") or f"HTTP_{st}"
            err_codes[f"{ec} ({key})"] += 1
        if st == 429:
            rate_limited += 1
        if rec.get("slow"):
            slow_reqs.append(rec)

    route_stats = []
    for route_key, recs in by_route.items():
        totals = sorted(float(r.get("total_ms", 0)) for r in recs)
        cnt = len(recs)
        errs = sum(1 for r in recs if int(r.get("status", 0)) >= 400)
        r429 = sum(1 for r in recs if int(r.get("status", 0)) == 429)
        avg_tls = sum(float(r.get("tls_ms", 0)) for r in recs) / cnt
        avg_q = sum(float(r.get("queue_ms", 0)) for r in recs) / cnt
        avg_h = sum(float(r.get("handle_ms", 0)) for r in recs) / cnt
        avg_w = sum(float(r.get("write_ms", 0)) for r in recs) / cnt
        route_stats.append(
            {
                "route": route_key,
                "count": cnt,
                "err_rate": round(errs / cnt, 4),
                "rate_limited": r429,
                "p50_ms": round(percentile(totals, 50), 2),
                "p95_ms": round(percentile(totals, 95), 2),
                "p99_ms": round(percentile(totals, 99), 2),
                "max_ms": round(max(totals), 2),
                "avg_tls_ms": round(avg_tls, 2),
                "avg_queue_ms": round(avg_q, 2),
                "avg_handle_ms": round(avg_h, 2),
                "avg_write_ms": round(avg_w, 2),
            }
        )

    route_stats.sort(key=lambda x: (-x["p95_ms"], -x["count"]))
    slow_reqs.sort(key=lambda x: -float(x.get("total_us", 0)))

    event_counts: Counter[str] = Counter()
    sse_close_reasons: Counter[str] = Counter()
    sse_durations: list[float] = []
    dm_modes: Counter[str] = Counter()
    ctl_actions: Counter[str] = Counter()
    tls_fails = 0
    room_relays = 0
    mail_ingests = 0

    for ev in events:
        k = str(ev.get("kind", ""))
        event_counts[k] += 1
        if k == "sse_close":
            sse_close_reasons[str(ev.get("reason", "unknown"))] += 1
            sse_durations.append(float(ev.get("duration_ms", 0)))
        elif k == "dm_relay":
            dm_modes[str(ev.get("delivered", "unknown"))] += 1
        elif k == "ctl_control":
            ctl_actions[str(ev.get("action", "unknown"))] += 1
        elif k == "tls_handshake_fail":
            tls_fails += 1
        elif k == "room_relay":
            room_relays += 1
        elif k == "mail_ingest":
            mail_ingests += 1

    peak_sse = max((int(m.get("peak_sse", 0)) for m in metrics), default=0)
    sse_dropped_full = sum(int(m.get("sse_dropped_full", 0)) for m in metrics)
    mail_gc_deleted = sum(int(m.get("mail_gc_deleted", 0)) for m in metrics)

    hints: list[str] = []
    if route_stats:
        hottest = route_stats[0]
        if hottest["avg_queue_ms"] > 10:
            hints.append(
                f"High hub queue wait on {hottest['route']} (avg_queue_ms={hottest['avg_queue_ms']}): consider sharding read routes off single hub_loop."
            )
        if hottest["avg_tls_ms"] > 30:
            hints.append(
                f"High TLS handshake latency on {hottest['route']} (avg_tls_ms={hottest['avg_tls_ms']}): consider TLS session resumption or persistent keepalive."
            )
    if sse_dropped_full > 0:
        hints.append(f"Dropped {sse_dropped_full} SSE events due to full client buffer (cap=64): raise per-client channel capacity.")
    if tls_fails > 0:
        hints.append(f"Observed {tls_fails} TLS handshake failures; inspect client cipher/SNI compatibility.")
    if not hints:
        hints.append("No bottlenecks detected in observed window.")

    return {
        "log_dir": str(log_dir),
        "date_filter": date_filter or "all",
        "summary": {
            "total_requests": total_reqs,
            "error_requests": err_reqs,
            "rate_limited_429": rate_limited,
            "slow_requests": len(slow_reqs),
            "events_total": len(events),
            "metric_snapshots": len(metrics),
            "peak_sse": peak_sse,
            "sse_dropped_full": sse_dropped_full,
            "mail_gc_deleted": mail_gc_deleted,
        },
        "routes": route_stats[:top_n],
        "top_errors": [{"error": k, "count": v} for k, v in err_codes.most_common(top_n)],
        "slowest_requests": [
            {
                "req_id": r.get("req_id"),
                "route": f"{r.get('method')} {r.get('route')}",
                "status": r.get("status"),
                "total_ms": r.get("total_ms"),
                "tls_ms": r.get("tls_ms"),
                "queue_ms": r.get("queue_ms"),
                "handle_ms": r.get("handle_ms"),
            }
            for r in slow_reqs[:top_n]
        ],
        "events_breakdown": dict(event_counts),
        "sse": {
            "close_reasons": dict(sse_close_reasons),
            "avg_duration_ms": round(sum(sse_durations) / len(sse_durations), 2) if sse_durations else 0.0,
        },
        "relay_and_mail": {
            "dm_delivery": dict(dm_modes),
            "room_relays": room_relays,
            "mail_ingests": mail_ingests,
        },
        "ctl_control_actions": dict(ctl_actions),
        "hints": hints,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Analyze fatext-server structured JSONL logs")
    ap.add_argument("--log-dir", default=os.environ.get("FATEXT_LOG_DIR", ""), help="Directory containing access/events/metrics JSONL files")
    ap.add_argument("--date", default="", help="Optional UTC date filter YYYY-MM-DD")
    ap.add_argument("--top", type=int, default=10, help="Max rows in route/error/slow tables")
    ap.add_argument("--json", action="store_true", help="Print machine-readable JSON")
    args = ap.parse_args()

    if not args.log_dir:
        print("Error: provide --log-dir or set FATEXT_LOG_DIR", file=sys.stderr)
        return 2
    log_dir = Path(args.log_dir)
    if not log_dir.is_dir():
        print(f"Error: log directory not found: {log_dir}", file=sys.stderr)
        return 1

    rep = analyze(log_dir, args.date or None, args.top)
    if args.json:
        print(json.dumps(rep, ensure_ascii=False))
        return 0

    s = rep["summary"]
    print(f"=== fatext-server Log Report ({rep['log_dir']}, date={rep['date_filter']}) ===")
    print(
        f"Requests: {s['total_requests']} | Errors: {s['error_requests']} | "
        f"429: {s['rate_limited_429']} | Slow: {s['slow_requests']} | "
        f"Peak SSE: {s['peak_sse']} | Dropped SSE: {s['sse_dropped_full']}"
    )
    print("\nTop Routes (by p95 latency):")
    for r in rep["routes"]:
        print(
            f"  {r['route']:32s} n={r['count']:<5d} err={r['err_rate']*100:5.1f}% "
            f"p50={r['p50_ms']:6.1f}ms p95={r['p95_ms']:6.1f}ms max={r['max_ms']:6.1f}ms "
            f"(tls={r['avg_tls_ms']:.1f} q={r['avg_queue_ms']:.1f} h={r['avg_handle_ms']:.1f} w={r['avg_write_ms']:.1f})"
        )
    if rep["top_errors"]:
        print("\nTop Errors:")
        for e in rep["top_errors"]:
            print(f"  {e['count']:5d}  {e['error']}")
    print("\nOptimization Hints:")
    for h in rep["hints"]:
        print(f"  - {h}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
