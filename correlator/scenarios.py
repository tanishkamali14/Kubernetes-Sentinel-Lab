#!/usr/bin/env python3
"""Load and validate scenarios/scenarios.json, the single list of attacks the runners execute and coverage checks."""
import argparse, json, sys
from pathlib import Path

DEFAULT = Path(__file__).resolve().parent.parent / 'scenarios' / 'scenarios.json'
EXPECT_KEYS = {'admission_denied': 'policy', 'falco_alert': 'rule', 'audit_exec': None}


def load(path=DEFAULT):
    data = json.loads(Path(path).read_text(encoding='utf-8-sig'))
    problems, seen = [], set()
    workload = data.get('workload') or {}
    if not workload.get('pod') or not workload.get('namespace'): problems.append('workload needs namespace and pod')
    for s in data.get('scenarios', []):
        sid = s.get('id', '?')
        if sid in seen: problems.append(f'{sid}: duplicate id')
        seen.add(sid)
        if s.get('kind') == 'admission' and not s.get('manifest'): problems.append(f'{sid}: admission scenario needs manifest')
        elif s.get('kind') == 'runtime' and not s.get('command'): problems.append(f'{sid}: runtime scenario needs command')
        elif s.get('kind') not in ('admission', 'runtime'): problems.append(f'{sid}: kind must be admission or runtime')
        if '"' in (s.get('command') or ''): problems.append(f'{sid}: command must not contain double quotes (Windows PowerShell 5.1 mangles them)')
        if not s.get('expect'): problems.append(f'{sid}: needs at least one expectation')
        for x in s.get('expect', []):
            if x.get('type') not in EXPECT_KEYS: problems.append(f"{sid}: unknown expectation type {x.get('type')!r}")
            elif EXPECT_KEYS[x['type']] and not x.get(EXPECT_KEYS[x['type']]): problems.append(f"{sid}: {x['type']} needs {EXPECT_KEYS[x['type']]}")
    if problems: raise ValueError('; '.join(problems))
    return data


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--file', type=Path, default=DEFAULT)
    p.add_argument('--tsv', action='store_true', help='print id, kind, target (manifest or command) per line for shell runners')
    args = p.parse_args()
    try: data = load(args.file)
    except (OSError, ValueError) as e: print(f'error: {e}', file=sys.stderr); return 2
    if args.tsv:
        for s in data['scenarios']: print(f"{s['id']}\t{s['kind']}\t{s.get('manifest') or s.get('command')}")
    else: print(f"{len(data['scenarios'])} scenarios OK")
    return 0


if __name__ == '__main__': raise SystemExit(main())
