#!/usr/bin/env python3
"""Group Kubernetes audit and Falco signals into scored per-pod incidents.

Scores are a triage heuristic built from temporal proximity and alert priority. They are not proof of
causation or compromise, so do not automate containment from this output alone.
"""
import argparse, hashlib, json, sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from correlate import read_jsonl
from events import PRIORITY_WEIGHT, TECHNIQUE_NAMES, audit_signal, falco_signal

SEVERITIES = (('critical', 70), ('high', 40), ('medium', 20), ('low', 0))
RANK = {name: i for i, (name, _) in enumerate(reversed(SEVERITIES))}


def iso(t):
    return datetime.fromtimestamp(t, timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z')


def collect_signals(audit, falco):
    """Normalize both sources; exec is long-running so one request may be audited twice (same auditID)."""
    seen, signals = set(), []
    for e in audit:
        s = audit_signal(e)
        if not s: continue
        key = (s['audit_id'], s['kind'])
        if s['audit_id'] and key in seen: continue
        seen.add(key); signals.append(s)
    signals += [s for e in falco if (s := falco_signal(e))]
    return sorted(signals, key=lambda s: s['ts'])


def severity(score):
    return next(name for name, floor in SEVERITIES if score >= floor)


def score_incident(execs, alerts, denied, policies, unmatched_shells):
    best = {}
    for a in alerts:  # one weight per distinct rule, so a noisy rule cannot dominate
        best[a['name']] = max(best.get(a['name'], 0), PRIORITY_WEIGHT.get(str(a['priority']).lower(), 5))
    total = sum(best.values())
    if execs and alerts: total += 15  # interactive API access followed by runtime detections
    if unmatched_shells: total += 20  # a shell with no matching exec audit did not come through the API server
    if execs and any('credential_access' in a['tactics'] for a in alerts): total += 10
    if denied: total += 10 + 5 * max(len(policies) - 1, 0)
    return min(total, 100)


def summarize(ns, pod, run, window):
    execs = [s for s in run if s['kind'] == 'exec']
    alerts = [s for s in run if s['kind'] == 'alert']
    denied = [s for s in run if s['kind'] == 'denied']
    shells = [a for a in alerts if a['shell']]
    unmatched = [a for a in shells if not any(abs(a['ts'] - e['ts']) <= window for e in execs)]
    policies = sorted({p for d in denied for p in d['policies']})
    findings = []
    if unmatched: findings.append('shell_without_exec_audit')
    if execs and not alerts: findings.append('exec_without_falco_alert')
    attribution = 'unattributed_shell' if unmatched else 'kubectl_exec' if shells else 'exec_only' if execs else 'none'
    techniques = sorted({t for a in alerts for t in a['techniques']})
    points = score_incident(execs, alerts, denied, policies, unmatched)
    start, end = run[0]['ts'], run[-1]['ts']
    return {'id': hashlib.sha1(f'{ns}/{pod}/{start}'.encode()).hexdigest()[:12], 'type': 'runtime' if (alerts or execs) else 'admission',
            'namespace': ns, 'pod': pod, 'start': iso(start), 'end': iso(end), 'duration_seconds': round(end - start, 3),
            'severity': severity(points), 'score': points, 'attribution': attribution, 'findings': findings,
            'actors': sorted({s['user'] for s in run if s['source'] == 'audit'}), 'rules': sorted({a['name'] for a in alerts}),
            'policies': policies, 'techniques': [{'id': t, 'name': TECHNIQUE_NAMES.get(t, '')} for t in techniques],
            'tactics': sorted({t for a in alerts for t in a['tactics']}), 'signals': len(run),
            'timeline': [{'time': iso(s['ts']), 'source': s['source'], 'kind': s['kind'], 'name': s['name'], 'detail': s['detail']} for s in run]}


def build_incidents(audit, falco, window=30.0, gap=120.0):
    groups = defaultdict(list)
    for s in collect_signals(audit, falco): groups[(s['namespace'], s['pod'])].append(s)
    out = []
    for (ns, pod), items in groups.items():
        run = [items[0]]
        for s in items[1:]:
            if s['ts'] - run[-1]['ts'] > gap:
                out.append(summarize(ns, pod, run, window)); run = []
            run.append(s)
        out.append(summarize(ns, pod, run, window))
    return sorted(out, key=lambda i: i['start'])


def table(rows):
    lines = [f"{'SEVERITY':<9} {'SCORE':>5}  {'POD':<28} {'START':<24} {'ATTRIBUTION':<19} DETAIL"]
    for i in rows:
        detail = ', '.join(i['rules'] + i['policies']) or '-'
        if len(detail) > 60: detail = detail[:57] + '...'
        lines.append(f"{i['severity']:<9} {i['score']:>5}  {i['namespace'] + '/' + i['pod']:<28} {i['start']:<24} {i['attribution']:<19} {detail}")
    return '\n'.join(lines)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--audit', required=True, type=Path); p.add_argument('--falco', required=True, type=Path)
    p.add_argument('--window-seconds', type=float, default=30, help='max gap between an exec audit event and a shell alert')
    p.add_argument('--gap-seconds', type=float, default=120, help='silence that closes one incident for a pod and starts the next')
    p.add_argument('--format', choices=('jsonl', 'json', 'table'), default='jsonl')
    p.add_argument('--min-severity', choices=tuple(RANK), default='low')
    args = p.parse_args()
    if args.window_seconds < 0 or args.gap_seconds < 0: p.error('--window-seconds and --gap-seconds must be non-negative')
    try: rows = build_incidents(list(read_jsonl(args.audit)), list(read_jsonl(args.falco)), args.window_seconds, args.gap_seconds)
    except (OSError, ValueError) as e: print(f'error: {e}', file=sys.stderr); return 2
    rows = [i for i in rows if RANK[i['severity']] >= RANK[args.min_severity]]
    if args.format == 'json': print(json.dumps(rows, indent=2))
    elif args.format == 'table': print(table(rows))
    else:
        for row in rows: print(json.dumps(row, separators=(',', ':')))
    return 0


if __name__ == '__main__': raise SystemExit(main())
