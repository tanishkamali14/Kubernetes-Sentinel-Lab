#!/usr/bin/env python3
"""Render a self-contained HTML report: summary, scored incidents, scenario coverage, observed ATT&CK techniques."""
import argparse, sys
from collections import Counter
from datetime import datetime, timezone
from html import escape as h
from pathlib import Path
from correlate import read_jsonl
from detection_coverage import evaluate, read_run
from incidents import RANK, build_incidents, collect_signals
import scenarios as scenario_file

CSS = """
:root{--bg:#f6f7f9;--card:#fff;--ink:#17202b;--muted:#5b6675;--line:#dde2e8;--crit:#b3261e;--high:#b45309;--med:#8a6d00;--low:#2e6b3d;--ok:#2e6b3d;--bad:#b3261e}
@media (prefers-color-scheme:dark){:root{--bg:#10151b;--card:#18202a;--ink:#e6ebf1;--muted:#97a3b3;--line:#2a3441;--crit:#ff8a80;--high:#ffb74d;--med:#e6c84f;--low:#7fcf95;--ok:#7fcf95;--bad:#ff8a80}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 system-ui,Segoe UI,sans-serif}
main{max-width:1100px;margin:0 auto;padding:24px 16px}h1{font-size:1.5rem;margin:0}h2{font-size:1.1rem;margin:32px 0 10px}
.sub{color:var(--muted);margin:4px 0 20px}.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px}
.tile{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px}.tile b{display:block;font-size:1.6rem}
.tile span{color:var(--muted);font-size:.85rem}.wrap{overflow-x:auto;background:var(--card);border:1px solid var(--line);border-radius:8px}
table{border-collapse:collapse;width:100%}th,td{padding:8px 10px;text-align:left;border-bottom:1px solid var(--line);vertical-align:top}
th{font-size:.8rem;color:var(--muted);text-transform:uppercase;letter-spacing:.04em}tr:last-child td{border-bottom:0}
.sev{font-weight:700;text-transform:uppercase;font-size:.78rem}.critical{color:var(--crit)}.high{color:var(--high)}.medium{color:var(--med)}.low,.covered{color:var(--low)}
.missed,.partial{color:var(--bad);font-weight:700}.not_run{color:var(--muted)}.chip{display:inline-block;border:1px solid var(--line);border-radius:999px;padding:0 8px;margin:1px 2px 1px 0;font-size:.8rem}
details summary{cursor:pointer;color:var(--muted)}.tl{margin:6px 0 0;padding-left:18px;font-size:.85rem}.mono{font-family:ui-monospace,Consolas,monospace;font-size:.82rem}
.note{color:var(--muted);font-size:.85rem}.nw{white-space:nowrap}main>.note{margin-top:28px}
"""


def chips(items): return ''.join(f'<span class="chip">{h(str(i))}</span>' for i in items) or '<span class="note">-</span>'


def incident_row(i):
    tl = ''.join(f"<li><span class='mono'>{h(t['time'][11:23])}</span> {h(t['source'])}/{h(t['kind'])}: {h(t['name'])} <span class='note'>{h(t['detail'][:140])}</span></li>" for t in i['timeline'])
    tech = chips(f"{t['id']} {t['name']}".strip() for t in i['techniques'])
    return (f"<tr><td><span class='sev {i['severity']}'>{i['severity']}</span><br>{i['score']}</td>"
            f"<td class='mono'>{h(i['namespace'])}/{h(i['pod'])}<br><span class='note nw'>{h(i['start'][:19])}Z &middot; {i['duration_seconds']}s</span></td>"
            f"<td>{h(i['attribution'])}<br>{chips(i['findings'])}</td><td>{chips(i['rules'] + i['policies'])}<br>{tech}</td>"
            f"<td>{chips(i['actors'])}<details><summary>{i['signals']} signals</summary><ul class='tl'>{tl}</ul></details></td></tr>")


def render(audit, falco, spec=None, run=None, window=30.0, gap=120.0):
    signals = collect_signals(audit, falco)
    incidents = sorted(build_incidents(audit, falco, window, gap), key=lambda i: (-RANK[i['severity']], -i['score'], i['start']))
    sev = Counter(i['severity'] for i in incidents)
    denied = [s for s in signals if s['kind'] == 'denied']
    techniques = Counter(t['id'] + '|' + t['name'] for i in incidents for t in i['techniques'])
    cov = evaluate(spec, signals, run, settle=15.0) if spec else None
    tiles = [(len(audit), 'audit records'), (len(falco), 'Falco events'), (len(incidents), 'incidents'),
             (sev['critical'] + sev['high'], 'critical + high'), (len(denied), 'admission denials')]
    if cov: tiles.append((f"{cov['coverage_percent']}%", f"scenario coverage ({cov['covered']}/{cov['total']})"))
    out = [f"<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
           f"<title>Runtime security report</title><style>{CSS}</style></head><body><main>",
           "<h1>Container runtime security report</h1>",
           f"<p class='sub'>Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M')} UTC &middot; correlation window {window:g}s &middot; incident gap {gap:g}s</p>",
           "<div class='tiles'>" + ''.join(f"<div class='tile'><b>{h(str(v))}</b><span>{h(k)}</span></div>" for v, k in tiles) + '</div>',
           "<h2>Incidents</h2><div class='wrap'><table><tr><th>Severity</th><th>Pod</th><th>Attribution</th><th>Rules, policies, techniques</th><th>Actors</th></tr>"
           + (''.join(incident_row(i) for i in incidents) or "<tr><td colspan='5'>No incidents.</td></tr>") + '</table></div>']
    if cov:
        out.append("<h2>Scenario coverage</h2><div class='wrap'><table><tr><th>ID</th><th>Scenario</th><th>Technique</th><th>Status</th><th>Missing</th></tr>"
                   + ''.join(f"<tr><td>{h(r['id'])}</td><td>{h(r['title'])}</td><td>{h(r['technique'] or '-')}</td>"
                             f"<td class='{r['status']}'>{r['status'].replace('_', ' ')}</td><td>{chips(r['missing'])}</td></tr>" for r in cov['scenarios'])
                   + '</table></div>')
    if techniques:
        out.append("<h2>ATT&amp;CK techniques observed</h2><div class='wrap'><table><tr><th>Technique</th><th>Name</th><th>Incidents</th></tr>"
                   + ''.join(f"<tr><td class='mono'>{h(k.split('|')[0])}</td><td>{h(k.split('|')[1] or '-')}</td><td>{n}</td></tr>" for k, n in sorted(techniques.items()))
                   + '</table></div>')
    out.append("<p class='note'>Scores are a triage heuristic from alert priority and temporal proximity, not proof of causation or compromise. "
               "Coverage means the expected signal appeared in the collected data for this lab's scenarios, not detection of real attackers.</p></main></body></html>")
    return ''.join(out)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--audit', required=True, type=Path); p.add_argument('--falco', required=True, type=Path)
    p.add_argument('--out', required=True, type=Path)
    p.add_argument('--scenarios', type=Path, default=scenario_file.DEFAULT); p.add_argument('--no-coverage', action='store_true')
    p.add_argument('--run', type=Path, help='scenario-run.jsonl written by the attack runners')
    p.add_argument('--window-seconds', type=float, default=30); p.add_argument('--gap-seconds', type=float, default=120)
    args = p.parse_args()
    try:
        spec = None if args.no_coverage else scenario_file.load(args.scenarios)
        page = render(list(read_jsonl(args.audit)), list(read_jsonl(args.falco)), spec, read_run(args.run) if args.run else None,
                      args.window_seconds, args.gap_seconds)
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(page, encoding='utf-8')
    except (OSError, ValueError) as e: print(f'error: {e}', file=sys.stderr); return 2
    print(f'wrote {args.out}')
    return 0


if __name__ == '__main__': raise SystemExit(main())
