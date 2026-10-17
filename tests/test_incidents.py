import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'correlator'))
from correlate import read_jsonl  # noqa: E402
from events import UNNAMED, audit_signal, denial_policies, falco_signal  # noqa: E402
from incidents import build_incidents, collect_signals, score_incident  # noqa: E402

ADV = ROOT / 'examples' / 'advanced'
KYVERNO_MSG = ('admission webhook "validate.kyverno.svc-fail" denied the request: \n\nresource Pod/default/x was blocked '
               'due to the following policies \n\ndisallow-hostpath-volumes:\n  block-hostpath: \'validation failure: no\'\n'
               'require-nonroot:\n  pod-run-as-nonroot: \'validation error: no\'')


def exec_event(ts='2026-01-01T12:00:00Z', pod='p', ns='default', aid='e1', code=200, user='alice'):
    return {'auditID': aid, 'verb': 'create', 'requestReceivedTimestamp': ts, 'user': {'username': user},
            'objectRef': {'resource': 'pods', 'subresource': 'exec', 'namespace': ns, 'name': pod}, 'responseStatus': {'code': code}}


def alert(rule='Detect shell in container', ts='2026-01-01T12:00:02Z', pod='p', ns='default', prio='Warning', tags=None):
    e = {'time': ts, 'rule': rule, 'priority': prio, 'output': 'o', 'output_fields': {'k8s.ns.name': ns, 'k8s.pod.name': pod, 'proc.cmdline': 'c'}}
    if tags is not None: e['tags'] = tags
    return e


class EventTests(unittest.TestCase):
    def test_denial_policies_parsed_from_kyverno_message(self):
        self.assertEqual(denial_policies(KYVERNO_MSG), ['disallow-hostpath-volumes', 'require-nonroot'])

    def test_denial_policies_empty_when_message_unrecognised(self):
        self.assertEqual(denial_policies('forbidden: User cannot create pods'), [])
        self.assertEqual(denial_policies(None), [])

    def test_denied_create_without_name_is_kept(self):
        e = {'auditID': 'd', 'verb': 'create', 'requestReceivedTimestamp': '2026-01-01T12:00:00Z', 'objectRef': {'resource': 'pods', 'namespace': 'default'},
             'responseStatus': {'code': 400, 'message': KYVERNO_MSG}}
        s = audit_signal(e)
        self.assertEqual((s['kind'], s['pod']), ('denied', UNNAMED))

    def test_api_races_and_kubelet_bootstrap_refusals_are_not_denial_signals(self):
        def denied(code, user='alice', ns='default'):
            return {'auditID': 'x', 'verb': 'create', 'requestReceivedTimestamp': '2026-01-01T12:00:00Z', 'user': {'username': user},
                    'objectRef': {'resource': 'pods', 'namespace': ns, 'name': 'p'}, 'responseStatus': {'code': code}}
        self.assertIsNone(audit_signal(denied(409)))                                              # AlreadyExists / Conflict
        self.assertIsNone(audit_signal(denied(404)))
        self.assertIsNone(audit_signal(denied(403, 'system:node:cp1', 'kube-system')))           # mirror pod before PriorityClass exists
        self.assertEqual(audit_signal(denied(403))['kind'], 'denied')                             # a user refused by RBAC is worth seeing
        self.assertEqual(audit_signal(denied(403, 'system:node:cp1', 'default'))['kind'], 'denied')  # only kube-system bootstrap is ignored
        self.assertEqual(audit_signal(denied(400))['kind'], 'denied')

    def test_successful_non_exec_audit_is_not_a_signal(self):
        self.assertIsNone(audit_signal({'verb': 'create', 'requestReceivedTimestamp': '2026-01-01T12:00:00Z',
                                        'objectRef': {'resource': 'pods', 'name': 'p'}, 'responseStatus': {'code': 201}}))

    def test_techniques_come_from_tags_then_fall_back_to_rule_name(self):
        tagged = falco_signal(alert(tags=['container', 'mitre_execution', 'T1059.004', 'T1105']))
        self.assertEqual((tagged['techniques'], tagged['tactics']), (['T1059.004', 'T1105'], ['execution']))
        untagged = falco_signal(alert())
        self.assertEqual(untagged['techniques'], ['T1059.004'])
        self.assertEqual(falco_signal(alert(rule='Some other rule'))['techniques'], [])

    def test_alert_without_pod_is_ignored(self):
        self.assertIsNone(falco_signal({'time': '2026-01-01T12:00:00Z', 'rule': 'x', 'output': 'no context'}))


class IncidentTests(unittest.TestCase):
    def test_exec_logged_at_two_stages_counts_once(self):
        sigs = collect_signals([exec_event(), exec_event()], [])
        self.assertEqual(len(sigs), 1)

    def test_exec_plus_shell_is_attributed_and_scored(self):
        [i] = build_incidents([exec_event()], [alert()])
        self.assertEqual((i['attribution'], i['findings'], i['actors']), ('kubectl_exec', [], ['alice']))
        self.assertEqual(i['score'], 15 + 15)  # shell warning + exec-with-alerts chain

    def test_shell_without_exec_is_flagged_and_scores_higher(self):
        [i] = build_incidents([], [alert()])
        self.assertEqual((i['attribution'], i['findings']), ('unattributed_shell', ['shell_without_exec_audit']))
        self.assertEqual(i['score'], 15 + 20)

    def test_exec_without_any_alert_is_a_finding(self):
        [i] = build_incidents([exec_event()], [])
        self.assertEqual((i['attribution'], i['findings'], i['severity']), ('exec_only', ['exec_without_falco_alert'], 'low'))

    def test_silence_longer_than_gap_splits_incidents(self):
        rows = build_incidents([], [alert(ts='2026-01-01T12:00:00Z'), alert(ts='2026-01-01T12:10:00Z')], gap=120)
        self.assertEqual(len(rows), 2)
        self.assertEqual(len(build_incidents([], [alert(ts='2026-01-01T12:00:00Z'), alert(ts='2026-01-01T12:01:00Z')], gap=120)), 1)

    def test_pods_never_share_an_incident(self):
        self.assertEqual(len(build_incidents([], [alert(pod='a'), alert(pod='b')])), 2)

    def test_same_rule_repeating_does_not_inflate_score(self):
        one = score_incident([], [{'name': 'r', 'priority': 'Warning', 'tactics': []}], [], [], [])
        many = score_incident([], [{'name': 'r', 'priority': 'Warning', 'tactics': []}] * 50, [], [], [])
        self.assertEqual(one, many)

    def test_score_is_capped(self):
        alerts = [{'name': f'r{i}', 'priority': 'Critical', 'tactics': ['credential_access']} for i in range(10)]
        self.assertEqual(score_incident([1], alerts, [], [], [1]), 100)

    def test_denial_only_incident_is_admission_type_and_low(self):
        denial = {'auditID': 'd', 'verb': 'create', 'requestReceivedTimestamp': '2026-01-01T12:00:00Z', 'user': {'username': 'alice'},
                  'objectRef': {'resource': 'pods', 'namespace': 'default', 'name': 'bad'}, 'responseStatus': {'code': 400, 'message': KYVERNO_MSG}}
        [i] = build_incidents([denial], [])
        self.assertEqual((i['type'], i['severity'], i['policies']), ('admission', 'low', ['disallow-hostpath-volumes', 'require-nonroot']))
        self.assertEqual(i['score'], 15)

    def test_credential_access_after_exec_adds_weight(self):
        cred = alert(rule='Detect read of shadow file in container', tags=['mitre_credential_access', 'T1003.008'])
        [i] = build_incidents([exec_event()], [alert(), cred])
        self.assertEqual(i['score'], 15 + 15 + 15 + 10)

    def test_advanced_fixture_end_to_end(self):
        rows = build_incidents(list(read_jsonl(ADV / 'audit.jsonl')), list(read_jsonl(ADV / 'falco.jsonl')))
        by_pod = {i['pod']: i for i in rows}
        self.assertEqual(set(by_pod), {'denied-privileged', 'denied-hostpath', 'denied-nonroot', 'runtime-lab', 'batch-job', 'payments-api'})
        self.assertEqual(by_pod['runtime-lab']['severity'], 'critical')
        self.assertEqual(by_pod['runtime-lab']['attribution'], 'kubectl_exec')
        self.assertEqual(by_pod['payments-api']['attribution'], 'unattributed_shell')
        self.assertEqual(by_pod['batch-job']['findings'], ['exec_without_falco_alert'])
        self.assertEqual(by_pod['denied-privileged']['policies'], ['disallow-privileged-containers'])
        self.assertEqual([t['id'] for t in by_pod['payments-api']['techniques']], ['T1059.004', 'T1496'])
        self.assertEqual(by_pod['payments-api']['techniques'][1]['name'], 'Resource Hijacking')


class CliTests(unittest.TestCase):
    def run_script(self, script, *args):
        return subprocess.run([sys.executable, str(ROOT / 'correlator' / script), '--audit', str(ADV / 'audit.jsonl'),
                               '--falco', str(ADV / 'falco.jsonl'), *args], capture_output=True, text=True)

    def test_min_severity_filters(self):
        res = self.run_script('incidents.py', '--min-severity', 'high')
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertEqual({json.loads(l)['pod'] for l in res.stdout.splitlines()}, {'runtime-lab', 'payments-api'})

    def test_table_and_json_formats(self):
        table = self.run_script('incidents.py', '--format', 'table').stdout
        self.assertTrue(table.startswith('SEVERITY'))
        self.assertEqual(len(json.loads(self.run_script('incidents.py', '--format', 'json').stdout)), 6)

    def test_negative_gap_rejected(self):
        self.assertEqual(self.run_script('incidents.py', '--gap-seconds', '-1').returncode, 2)

    def test_metrics_reports_new_fields(self):
        out = json.loads(self.run_script('metrics.py').stdout)
        self.assertEqual(out['denied_by_policy'], {'disallow-hostpath-volumes': 1, 'disallow-privileged-containers': 1, 'require-nonroot': 1})
        self.assertEqual(out['shell_alerts_without_exec_audit'], 1)
        self.assertEqual(out['incidents'], 6)
        self.assertEqual(out['incidents_by_severity'], {'low': 4, 'critical': 2})
        self.assertIn('T1496', out['techniques_observed'])


if __name__ == '__main__':
    unittest.main()
