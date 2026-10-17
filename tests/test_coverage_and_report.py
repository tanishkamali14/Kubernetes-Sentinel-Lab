import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'correlator'))
import scenarios as scenario_file  # noqa: E402
from correlate import read_jsonl  # noqa: E402
from detection_coverage import evaluate, read_run  # noqa: E402
from incidents import collect_signals  # noqa: E402
from report import render  # noqa: E402

ADV = ROOT / 'examples' / 'advanced'


def fixture():
    return list(read_jsonl(ADV / 'audit.jsonl')), list(read_jsonl(ADV / 'falco.jsonl')), read_run(ADV / 'scenario-run.jsonl')


class ScenarioFileTests(unittest.TestCase):
    def test_bundled_scenarios_validate(self):
        spec = scenario_file.load()
        self.assertEqual(len(spec['scenarios']), 8)

    def test_validation_catches_problems(self):
        def check(doc, text):
            with tempfile.TemporaryDirectory() as d:
                p = Path(d, 's.json'); p.write_text(json.dumps(doc), encoding='utf-8')
                with self.assertRaisesRegex(ValueError, text): scenario_file.load(p)
        w = {'namespace': 'default', 'pod': 'p'}
        ok = {'id': 'R1', 'kind': 'runtime', 'command': 'id', 'expect': [{'type': 'audit_exec'}]}
        check({'workload': w, 'scenarios': [ok, ok]}, 'duplicate id')
        check({'workload': w, 'scenarios': [{**ok, 'command': 'echo "x"'}]}, 'double quotes')
        check({'workload': w, 'scenarios': [{**ok, 'expect': [{'type': 'falco_alert'}]}]}, 'needs rule')
        check({'workload': w, 'scenarios': [{**ok, 'expect': [{'type': 'nope'}]}]}, 'unknown expectation')
        check({'workload': w, 'scenarios': [{'id': 'A', 'kind': 'admission', 'expect': [{'type': 'audit_exec'}]}]}, 'needs manifest')
        check({'workload': {}, 'scenarios': []}, 'workload')

    def test_tsv_output_is_one_line_per_scenario(self):
        res = subprocess.run([sys.executable, str(ROOT / 'correlator' / 'scenarios.py'), '--tsv'], capture_output=True, text=True)
        rows = [l.split('\t') for l in res.stdout.splitlines()]
        self.assertEqual(len(rows), 8)
        self.assertTrue(all(len(r) == 3 for r in rows))
        self.assertEqual(rows[0][:2], ['A1', 'admission'])

    def test_referenced_manifests_policies_and_rules_exist(self):
        spec = scenario_file.load()
        policies = ''.join((ROOT / 'kyverno' / f).read_text(encoding='utf-8') for f in ('baseline-policies.yaml', 'advanced-policies.yaml'))
        rules = {}
        for f in (ROOT / 'falco').glob('*.yaml'):
            text = f.read_text(encoding='utf-8')
            for m in re.finditer(r'^- rule: (.+)$', text, flags=re.M):
                tags = re.search(r'tags: \[(.*?)\]', text[m.end():]).group(1)
                rules[m.group(1)] = tags
        for s in spec['scenarios']:
            if s['kind'] == 'admission': self.assertTrue((ROOT / s['manifest']).is_file(), s['id'])
            for x in s['expect']:
                if x['type'] == 'admission_denied': self.assertRegex(policies, rf'name: {re.escape(x["policy"])}\n', s['id'])
                if x['type'] == 'falco_alert':
                    self.assertIn(x['rule'], rules, s['id'])
                    if s.get('technique'): self.assertIn(s['technique'], rules[x['rule']], f"{s['id']} technique not in rule tags")


class CoverageTests(unittest.TestCase):
    def setUp(self):
        self.audit, self.falco, self.run = fixture()
        self.spec = scenario_file.load()
        self.signals = collect_signals(self.audit, self.falco)

    def test_fixture_run_has_exactly_one_gap(self):
        res = evaluate(self.spec, self.signals, self.run)
        status = {r['id']: r['status'] for r in res['scenarios']}
        self.assertEqual(status['A4'], 'missed')
        self.assertEqual([k for k, v in status.items() if v != 'covered'], ['A4'])
        self.assertEqual((res['covered'], res['total'], res['coverage_percent']), (7, 8, 87.5))

    def test_alert_outside_the_scenario_window_does_not_count(self):
        shifted = dict(self.run)
        shifted['R2'] = {'id': 'R2', 'started': '2026-01-01T09:00:00Z', 'finished': '2026-01-01T09:00:01Z'}
        status = {r['id']: r['status'] for r in evaluate(self.spec, self.signals, shifted)['scenarios']}
        self.assertEqual(status['R2'], 'missed')

    def test_scenario_missing_from_run_log_is_not_run(self):
        partial = {k: v for k, v in self.run.items() if k != 'R3'}
        res = evaluate(self.spec, self.signals, partial)
        self.assertEqual(next(r for r in res['scenarios'] if r['id'] == 'R3')['status'], 'not_run')
        self.assertEqual(res['not_run'], 1)

    def test_partial_when_only_some_expectations_seen(self):
        no_exec = [s for s in self.signals if s['kind'] != 'exec']
        r1 = next(r for r in evaluate(self.spec, no_exec, self.run)['scenarios'] if r['id'] == 'R1')
        self.assertEqual((r1['status'], r1['missing']), ('partial', ['audit_exec']))

    def test_without_run_log_since_filters_old_signals(self):
        self.assertEqual(evaluate(self.spec, self.signals)['covered'], 7)
        later = evaluate(self.spec, self.signals, since=1_800_000_000)['covered']  # after every fixture signal
        self.assertEqual(later, 0)

    def test_unnamed_denial_still_counts(self):
        denial = {'auditID': 'x', 'verb': 'create', 'requestReceivedTimestamp': '2026-01-01T11:59:00.100Z', 'user': {'username': 'a'},
                  'objectRef': {'resource': 'pods', 'namespace': 'default'},
                  'responseStatus': {'code': 400, 'message': 'blocked due to the following policies \n\nrequire-drop-all-capabilities:\n  r: \'x\''}}
        sigs = collect_signals(self.audit + [denial], self.falco)
        self.assertEqual(evaluate(self.spec, sigs, self.run)['covered'], 8)

    def test_cli_fail_on_gap_exit_code(self):
        base = [sys.executable, str(ROOT / 'correlator' / 'detection_coverage.py'), '--audit', str(ADV / 'audit.jsonl'),
                '--falco', str(ADV / 'falco.jsonl'), '--run', str(ADV / 'scenario-run.jsonl')]
        self.assertEqual(subprocess.run(base, capture_output=True).returncode, 0)
        self.assertEqual(subprocess.run(base + ['--fail-on-gap'], capture_output=True).returncode, 1)
        self.assertEqual(subprocess.run(base + ['--since', 'garbage'], capture_output=True).returncode, 2)

    def test_run_log_written_by_powershell_style_timestamps_parses(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d, 'run.jsonl')
            p.write_text('{"id":"R1","started":"2026-01-01T12:00:00.0000000Z","finished":"2026-01-01T12:00:01.123Z","result":"ok"}\n', encoding='utf-8')
            self.assertEqual(evaluate(self.spec, self.signals, read_run(p))['scenarios'][4]['status'], 'covered')


class ReportTests(unittest.TestCase):
    def test_report_contains_sections_and_is_self_contained(self):
        audit, falco, run = fixture()
        page = render(audit, falco, scenario_file.load(), run)
        for needle in ('Incidents', 'Scenario coverage', 'ATT&amp;CK techniques observed', '87.5%', 'unattributed_shell', 'prod/payments-api', 'T1496'):
            self.assertIn(needle, page)
        self.assertNotRegex(page, r'(?:src|href)=["\']?https?://')
        self.assertNotIn('<script', page)

    def test_untrusted_values_are_escaped(self):
        evil = '<img src=x onerror=alert(1)>'
        audit = [{'auditID': 'x', 'verb': 'create', 'requestReceivedTimestamp': '2026-01-01T12:00:00Z', 'user': {'username': evil},
                  'objectRef': {'resource': 'pods', 'subresource': 'exec', 'namespace': 'default', 'name': evil}, 'responseStatus': {'code': 200}}]
        falco = [{'time': '2026-01-01T12:00:01Z', 'rule': evil + ' shell', 'priority': 'Warning', 'output': evil,
                  'output_fields': {'k8s.ns.name': 'default', 'k8s.pod.name': evil, 'proc.cmdline': evil}}]
        page = render(audit, falco)
        self.assertNotIn(evil, page)
        self.assertIn('&lt;img src=x onerror=alert(1)&gt;', page)

    def test_empty_inputs_render(self):
        self.assertIn('No incidents.', render([], []))

    def test_cli_writes_file_and_supports_no_coverage(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d, 'sub', 'r.html')
            res = subprocess.run([sys.executable, str(ROOT / 'correlator' / 'report.py'), '--audit', str(ADV / 'audit.jsonl'),
                                  '--falco', str(ADV / 'falco.jsonl'), '--no-coverage', '--out', str(out)], capture_output=True, text=True)
            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertNotIn('Scenario coverage', out.read_text(encoding='utf-8'))

    def test_bundled_example_report_is_current(self):
        audit, falco, run = fixture()
        committed = (ADV / 'report.html').read_text(encoding='utf-8')
        fresh = render(audit, falco, scenario_file.load(), run)
        strip = lambda s: re.sub(r'Generated [^&]*UTC', 'Generated', s)
        self.assertEqual(strip(committed), strip(fresh), 'examples/advanced/report.html is stale; re-run correlator/report.py')


if __name__ == '__main__':
    unittest.main()
