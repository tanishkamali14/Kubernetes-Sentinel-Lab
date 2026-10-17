#!/usr/bin/env python3
"""Normalize Kubernetes audit records and Falco alerts into one signal shape."""
import re
from correlate import audit_exec, falco_alert, timestamp

TECHNIQUE = re.compile(r'^T\d{4}(?:\.\d{3})?$')
# Local lookup for report labels; an ID missing here is shown without a name.
TECHNIQUE_NAMES = {
    'T1003.008': '/etc/passwd and /etc/shadow', 'T1046': 'Network Service Discovery',
    'T1059.004': 'Unix Shell', 'T1095': 'Non-Application Layer Protocol', 'T1105': 'Ingress Tool Transfer',
    'T1496': 'Resource Hijacking', 'T1552.007': 'Container API', 'T1613': 'Container and Resource Discovery',
}
# Used only when an alert carries no tags (older exports, hand-written fixtures).
RULE_FALLBACK = {
    'Detect shell in container': (['T1059.004'], ['execution']),
    'Detect read of shadow file in container': (['T1003.008'], ['credential_access']),
    'Detect service account token access in container': (['T1552.007'], ['credential_access']),
}
PRIORITY_WEIGHT = {'emergency': 40, 'alert': 40, 'critical': 40, 'error': 30, 'warning': 15, 'notice': 5,
                   'informational': 2, 'info': 2, 'debug': 1}
UNNAMED = '(unnamed)'
# NotFound, Conflict and Gone are ordinary API races (a mirror pod that already exists), not refusals.
NOT_REFUSALS = {404, 409, 410}
DENIAL_BLOCK = re.compile(r'following polic(?:y|ies)(.*)', re.S | re.I)
POLICY_LINE = re.compile(r'^\s*([a-z0-9][a-z0-9.-]*):\s*$', re.M)


def denial_policies(message):
    """Kyverno lists blocking policy names on their own lines after 'blocked due to the following policies'."""
    m = DENIAL_BLOCK.search(str(message or ''))
    return sorted(set(POLICY_LINE.findall(m.group(1)))) if m else []


def is_bootstrap(sig):
    """The kubelet registers control-plane mirror pods at node start; some are refused (403, no PriorityClass yet)."""
    return str(sig['user']).startswith('system:node:') and sig['namespace'] == 'kube-system'


def audit_signal(e):
    ref = e.get('objectRef') or {}
    if ref.get('resource') != 'pods': return None
    status = e.get('responseStatus') or {}
    code = status.get('code') if isinstance(status.get('code'), int) else None
    sig = {'source': 'audit', 'ts': timestamp(e.get('requestReceivedTimestamp') or e.get('stageTimestamp') or e.get('time')),
           'namespace': ref.get('namespace', 'default'), 'pod': ref.get('name'), 'user': (e.get('user') or {}).get('username', 'unknown'),
           'audit_id': e.get('auditID'), 'verb': e.get('verb'), 'subresource': ref.get('subresource'), 'code': code}
    if sig['ts'] is None: return None
    if code is not None and code >= 400:
        if code in NOT_REFUSALS or is_bootstrap(sig): return None
        policies = denial_policies(status.get('message'))
        what = ', '.join(policies) or f"{ref.get('subresource') or 'pods'} {e.get('verb')}"
        # A rejected create can be audited before the object has a name (generateName).
        return {**sig, 'pod': sig['pod'] or UNNAMED, 'kind': 'denied', 'policies': policies, 'name': what,
                'detail': str(status.get('message') or '')[:300]}
    if not sig['pod']: return None
    if audit_exec(e):
        return {**sig, 'kind': 'exec', 'name': 'pods/exec', 'detail': f"exec by {sig['user']}"}
    return None


def falco_signal(e):
    a = falco_alert(e)
    if not a or a['ts'] is None: return None
    tags = [str(t) for t in a['tags']]
    techniques = [t for t in tags if TECHNIQUE.match(t)]
    tactics = [t[len('mitre_'):] for t in tags if t.startswith('mitre_')]
    if not techniques and not tactics:
        techniques, tactics = RULE_FALLBACK.get(a['rule'], ([], []))
    return {'source': 'falco', 'kind': 'alert', 'ts': a['ts'], 'namespace': a['namespace'], 'pod': a['pod'], 'name': a['rule'],
            'priority': a['priority'], 'techniques': techniques, 'tactics': tactics, 'shell': 'shell' in a['rule'].lower(),
            'detail': a['command'] or a['output']}
