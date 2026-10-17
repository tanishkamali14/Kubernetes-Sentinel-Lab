#!/usr/bin/env python3
"""Check which scenarios from scenarios/scenarios.json produced the policy denial or detection they expect.

With --run (the log the attack runners write) each expectation must be observed inside that scenario's time
window, so an alert left over from an earlier run cannot satisfy a later scenario. Without it, any matching
signal at or after --since counts. Coverage here means "the expected signal appeared in the collected data",
which is evidence about this lab's controls, not a statement about detection of real attackers.
"""
import argparse, json, sys
from pathlib import Path
from correlate import read_jsonl, timestamp
from events import UNNAMED
from incidents import collect_signals
import scenarios as scenario_file


def read_run(path):
    return {r['id']: r for r in read_jsonl(path) if r.get('id')}


def observed(expect, signals, pod, ns, lo, hi):
    for s in signals:
        if not (lo <= s['ts'] <= hi): continue
        t = expect['type']
        if t == 'admission_denied' and s['kind'] == 'denied' and expect['policy'] in s['policies'] and s['pod'] in (pod, UNNAMED): return s
        if t == 'audit_exec' and s['kind'] == 'exec' and s['pod'] == pod and s['namespace'] == ns: return s
        if t == 'falco_alert' and s['kind'] == 'alert' and s['name'] == expect['rule'] and s['pod'] == pod and s['namespace'] == ns: return s
    return None


def evaluate(spec, signals, run=None, since=None, settle=15.0):
    work = spec['workload']; rows = []
    for sc in spec['scenarios']:
        lo, hi = (since or float('-inf')), float('inf')
        if run is not None:
            r = run.get(sc['id'])
            if not r or timestamp(r.get('started')) is None:
                rows.append({'id': sc['id'], 'title': sc['title'], 'technique': sc.get('technique'), 'status': 'not_run', 'observed': [], 'missing': []})
                continue
            lo, hi = timestamp(r['started']) - 2, (timestamp(r.get('finished')) or timestamp(r['started'])) + settle
        pod = sc.get('pod') or work['pod']
        got, missing = [], []
        for x in sc['expect']:
            hit = observed(x, signals, pod, work['namespace'], lo, hi)
            (got if hit else missing).append(x.get('policy') or x.get('rule') or x['type'])
        rows.append({'id': sc['id'], 'title': sc['title'], 'technique': sc.get('technique'), 'observed': got, 'missing': missing,
                     'status': 'covered' if not missing else 'partial' if got else 'missed'})
    ran = [r for r in rows if r['status'] != 'not_run']
    covered = sum(r['status'] == 'covered' for r in rows)
    return {'scenarios': rows, 'covered': covered, 'total': len(rows), 'not_run': len(rows) - len(ran),
            'coverage_percent': round(100 * covered / len(rows), 1) if rows else 0.0}


def table(result):
    lines = [f"{'ID':<4} {'STATUS':<8} {'TECHNIQUE':<10} {'SCENARIO':<48} MISSING"]
    for r in result['scenarios']:
        lines.append(f"{r['id']:<4} {r['status']:<8} {r['technique'] or '-':<10} {r['title']:<48} {', '.join(r['missing']) or '-'}")
    lines.append(f"\ncovered {result['covered']}/{result['total']} ({result['coverage_percent']}%), not run: {result['not_run']}")
    return '\n'.join(lines)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--audit', required=True, type=Path); p.add_argument('--falco', required=True, type=Path)
    p.add_argument('--scenarios', type=Path, default=scenario_file.DEFAULT)
    p.add_argument('--run', type=Path, help='scenario-run.jsonl written by the attack runners')
    p.add_argument('--since', help='ignore signals before this ISO-8601 time (used when --run is absent)')
    p.add_argument('--settle-seconds', type=float, default=15, help='how long after a scenario ends its signals may still arrive')
    p.add_argument('--format', choices=('json', 'table'), default='json')
    p.add_argument('--fail-on-gap', action='store_true', help='exit 1 unless every scenario is covered')
    args = p.parse_args()
    since = timestamp(args.since) if args.since else None
    if args.since and since is None: p.error('--since must be an ISO-8601 time')
    try:
        spec = scenario_file.load(args.scenarios)
        run = read_run(args.run) if args.run else None
        result = evaluate(spec, collect_signals(list(read_jsonl(args.audit)), list(read_jsonl(args.falco))), run, since, args.settle_seconds)
    except (OSError, ValueError) as e: print(f'error: {e}', file=sys.stderr); return 2
    print(table(result) if args.format == 'table' else json.dumps(result, indent=2))
    return 1 if args.fail_on_gap and result['covered'] != result['total'] else 0


if __name__ == '__main__': raise SystemExit(main())
