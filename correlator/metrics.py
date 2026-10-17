#!/usr/bin/env python3
"""Summarize audit denials/execs and Falco alerts from JSONL snapshots."""
import argparse,json,sys
from collections import Counter
from pathlib import Path
from correlate import correlate,read_jsonl
from incidents import build_incidents,collect_signals
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--audit',required=True,type=Path); p.add_argument('--falco',required=True,type=Path)
p.add_argument('--window-seconds',type=float,default=30); a=p.parse_args()
try:
 audit=list(read_jsonl(a.audit)); falco=list(read_jsonl(a.falco))
except (OSError,ValueError) as e:
 print(f'error: {e}',file=sys.stderr); raise SystemExit(2)
rules=Counter(str(e.get('rule','unknown')) for e in falco if e.get('rule'))
denied=sum(1 for e in audit if isinstance((e.get('responseStatus') or {}).get('code'),int) and (e.get('responseStatus') or {}).get('code',0)>=400)
# exec is a long-running request, so one request can be logged at ResponseStarted and ResponseComplete.
execs=len({e.get('auditID') or id(e) for e in audit if (e.get('objectRef') or {}).get('resource')=='pods' and (e.get('objectRef') or {}).get('subresource')=='exec'})
matches=correlate(audit,falco,a.window_seconds)
incidents=build_incidents(audit,falco,a.window_seconds)
by_policy=Counter(p for s in collect_signals(audit,falco) if s['kind']=='denied' for p in s['policies'])
print(json.dumps({'audit_records':len(audit),'falco_events':len(falco),'pod_exec_requests':execs,'denied_api_requests':denied,
                  'denied_by_policy':dict(sorted(by_policy.items())),'falco_alerts_by_rule':dict(sorted(rules.items())),
                  'correlated_exec_shell_matches':len(matches),
                  'shell_alerts_without_exec_audit':sum('shell_without_exec_audit' in i['findings'] for i in incidents),
                  'incidents':len(incidents),'incidents_by_severity':dict(Counter(i['severity'] for i in incidents)),
                  'techniques_observed':sorted({t['id'] for i in incidents for t in i['techniques']})},indent=2))
