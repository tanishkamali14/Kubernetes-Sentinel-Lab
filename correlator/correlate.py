#!/usr/bin/env python3
"""Join Kubernetes pods/exec audit records with Falco shell alerts."""
import argparse, json, re, sys
from datetime import datetime, timezone
from pathlib import Path

def timestamp(v):
    if v is None: return None
    if isinstance(v,(int,float)):
        n=float(v); return n/1e9 if n>1e17 else n/1e3 if n>1e11 else n
    if not isinstance(v,str) or not v.strip(): return None
    try: return timestamp(float(v))
    except ValueError: pass
    try:
        # Python 3.10 only parses 3- or 6-digit fractions; Falco emits 9 (nanoseconds).
        v=re.sub(r'\.(\d+)',lambda m:'.'+m.group(1)[:6].ljust(6,'0'),v.strip())
        dt=datetime.fromisoformat(v.replace('Z','+00:00'))
        return (dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).timestamp()
    except ValueError: return None

def read_jsonl(path):
    with Path(path).open(encoding='utf-8-sig') as f:
        for no,line in enumerate(f,1):
            if not line.strip(): continue
            try: obj=json.loads(line)
            except json.JSONDecodeError as e: raise ValueError(f'{path}:{no}: invalid JSON ({e.msg})') from e
            if isinstance(obj,dict): yield obj

def audit_exec(e):
    ref=e.get('objectRef') or {}
    # SPDY exec is audited as create; WebSocket exec (kubectl >= 1.31) can show up as get.
    if ref.get('resource')!='pods' or ref.get('subresource')!='exec' or e.get('verb') not in ('create','connect','get'): return None
    return {'ts':timestamp(e.get('requestReceivedTimestamp') or e.get('stageTimestamp') or e.get('time')),
            'namespace':ref.get('namespace','default'),'pod':ref.get('name'),
            'user':(e.get('user') or {}).get('username','unknown'),'audit_id':e.get('auditID')}

def falco_alert(e):
    fields=e.get('output_fields') or e.get('outputFields') or {}; output=str(e.get('output',''))
    ns=fields.get('k8s.ns.name') or fields.get('k8s.namespace.name')
    pod=fields.get('k8s.pod.name')
    if not ns:
        m=re.search(r'\bnamespace=([^\s)]+)',output); ns=m.group(1) if m else None
    if not pod:
        m=re.search(r'\bpod=([^\s)]+)',output); pod=m.group(1) if m else None
    if not ns or not pod: return None
    return {'ts':timestamp(e.get('time') or e.get('evt.time') or e.get('timestamp')),'namespace':ns,'pod':pod,
            'rule':str(e.get('rule','')),'priority':e.get('priority'),'process':fields.get('proc.name'),
            'command':fields.get('proc.cmdline'),'container_id':fields.get('container.id'),
            'tags':e.get('tags') or [],'output':output}

def falco_shell(e):
    a=falco_alert(e)
    return a if a and 'shell' in a['rule'].lower() else None

def correlate(audit,falco,window):
    aa=[a for x in audit if (a:=audit_exec(x)) and a['ts'] is not None and a['pod']]
    ff=[f for x in falco if (f:=falco_shell(x)) and f['ts'] is not None]
    result=[]
    for f in ff:
        candidates=[a for a in aa if a['namespace']==f['namespace'] and a['pod']==f['pod'] and abs(f['ts']-a['ts'])<=window]
        if not candidates: continue
        a=min(candidates,key=lambda x:abs(f['ts']-x['ts']))
        fmt=lambda t:datetime.fromtimestamp(t,timezone.utc).isoformat().replace('+00:00','Z')
        result.append({'type':'kubernetes_exec_correlated_with_falco_shell','namespace':f['namespace'],'pod':f['pod'],
          'user':a['user'],'audit_id':a['audit_id'],'audit_time':fmt(a['ts']),'falco_time':fmt(f['ts']),
          'delta_seconds':round(f['ts']-a['ts'],3),'falco_rule':f['rule'],'priority':f['priority'],
          'process':f['process'],'command':f['command'],'container_id':f['container_id']})
    return result

def main():
    p=argparse.ArgumentParser(description=__doc__); p.add_argument('--audit',required=True,type=Path); p.add_argument('--falco',required=True,type=Path)
    p.add_argument('--window-seconds',type=float,default=30); args=p.parse_args()
    if args.window_seconds<0: p.error('--window-seconds must be non-negative')
    try: rows=correlate(list(read_jsonl(args.audit)),list(read_jsonl(args.falco)),args.window_seconds)
    except (OSError,ValueError) as e: print(f'error: {e}',file=sys.stderr); return 2
    for row in rows: print(json.dumps(row,separators=(',',':')))
    return 0
if __name__=='__main__': raise SystemExit(main())
