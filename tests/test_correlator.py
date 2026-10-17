import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'correlator'))
from correlate import audit_exec, correlate, falco_shell, read_jsonl, timestamp  # noqa: E402


def exec_event(ts='2026-01-01T12:00:00.000000Z', pod='runtime-lab', ns='default', verb='create', audit_id='a1', code=200):
    return {'auditID': audit_id, 'verb': verb, 'requestReceivedTimestamp': ts, 'user': {'username': 'alice'},
            'objectRef': {'resource': 'pods', 'subresource': 'exec', 'namespace': ns, 'name': pod},
            'responseStatus': {'code': code}}


def shell_alert(ts='2026-01-01T12:00:02.000000000Z', pod='runtime-lab', ns='default'):
    return {'time': ts, 'rule': 'Detect shell in container', 'priority': 'Warning', 'output': 'x',
            'output_fields': {'k8s.ns.name': ns, 'k8s.pod.name': pod, 'proc.name': 'sh', 'proc.cmdline': 'sh -c id'}}


class TimestampTests(unittest.TestCase):
    def test_fraction_lengths(self):
        base = timestamp('2026-01-01T12:00:00Z')
        for frac in ('.5', '.50', '.500', '.500000', '.500000000'):
            self.assertAlmostEqual(timestamp(f'2026-01-01T12:00:00{frac}Z'), base + 0.5, places=6, msg=frac)

    def test_numeric_units(self):
        self.assertEqual(timestamp(1_700_000_000), 1_700_000_000)
        self.assertEqual(timestamp(1_700_000_000_000), 1_700_000_000)
        self.assertEqual(timestamp(1_700_000_000_000_000_000), 1_700_000_000)

    def test_garbage(self):
        self.assertIsNone(timestamp('not a time'))
        self.assertIsNone(timestamp(None))


class CorrelateTests(unittest.TestCase):
    def test_match_within_window(self):
        rows = correlate([exec_event()], [shell_alert()], 30)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['delta_seconds'], 2.0)
        self.assertEqual(rows[0]['user'], 'alice')

    def test_outside_window(self):
        self.assertEqual(correlate([exec_event()], [shell_alert(ts='2026-01-01T12:05:00Z')], 30), [])

    def test_other_pod_or_namespace(self):
        self.assertEqual(correlate([exec_event()], [shell_alert(pod='other')], 30), [])
        self.assertEqual(correlate([exec_event()], [shell_alert(ns='prod')], 30), [])

    def test_picks_closest_exec(self):
        audit = [exec_event(ts='2026-01-01T11:59:50Z', audit_id='far'), exec_event(ts='2026-01-01T12:00:01Z', audit_id='near')]
        self.assertEqual(correlate(audit, [shell_alert()], 30)[0]['audit_id'], 'near')

    def test_websocket_exec_verb_get(self):
        self.assertIsNotNone(audit_exec(exec_event(verb='get')))
        self.assertIsNone(audit_exec(exec_event(verb='delete')))

    def test_non_exec_and_non_shell_ignored(self):
        create_pod = {'verb': 'create', 'objectRef': {'resource': 'pods', 'name': 'p'}}
        self.assertIsNone(audit_exec(create_pod))
        shadow = shell_alert()
        shadow['rule'] = 'Detect read of shadow file in container'
        self.assertIsNone(falco_shell(shadow))

    def test_falco_fields_fall_back_to_output_text(self):
        alert = {'time': '2026-01-01T12:00:02Z', 'rule': 'Detect shell in container',
                 'output': 'Shell process (namespace=default pod=runtime-lab)'}
        self.assertEqual(falco_shell(alert)['pod'], 'runtime-lab')


class CliTests(unittest.TestCase):
    def run_cli(self, script, audit, falco, *extra):
        with tempfile.TemporaryDirectory() as d:
            a, f = Path(d, 'audit.jsonl'), Path(d, 'falco.jsonl')
            a.write_text('\n'.join(json.dumps(x) for x in audit), encoding='utf-8')
            f.write_text('\n'.join(json.dumps(x) for x in falco), encoding='utf-8')
            return subprocess.run([sys.executable, str(ROOT / 'correlator' / script), '--audit', str(a), '--falco', str(f), *extra],
                                  capture_output=True, text=True)

    def test_metrics_dedupes_long_running_exec_and_counts_denials(self):
        audit = [exec_event(audit_id='x'), exec_event(audit_id='x'),
                 {'auditID': 'd', 'verb': 'create', 'objectRef': {'resource': 'pods', 'name': 'bad'}, 'responseStatus': {'code': 400}}]
        res = self.run_cli('metrics.py', audit, [shell_alert()])
        self.assertEqual(res.returncode, 0, res.stderr)
        out = json.loads(res.stdout)
        self.assertEqual(out['pod_exec_requests'], 1)
        self.assertEqual(out['denied_api_requests'], 1)
        self.assertEqual(out['correlated_exec_shell_matches'], 1)
        self.assertEqual(out['falco_alerts_by_rule'], {'Detect shell in container': 1})

    def test_correlate_emits_one_json_object_per_line(self):
        res = self.run_cli('correlate.py', [exec_event()], [shell_alert()])
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertEqual(len(res.stdout.strip().splitlines()), 1)
        self.assertEqual(json.loads(res.stdout)['type'], 'kubernetes_exec_correlated_with_falco_shell')

    def test_invalid_json_reports_file_and_line(self):
        with tempfile.TemporaryDirectory() as d:
            bad = Path(d, 'bad.jsonl')
            bad.write_text('{"ok":1}\n{nope\n', encoding='utf-8')
            with self.assertRaisesRegex(ValueError, r'bad\.jsonl:2'):
                list(read_jsonl(bad))

    def test_corrupt_falco_line_is_skipped_with_a_warning_not_fatal(self):
        # Seen in CI: Falco wrote an alert and one of its own log messages into the same line.
        good = json.dumps(shell_alert())
        corrupt = '{"hostname":"n","output":"x","rule":"Detect service account token access in container","tags":["T1552.007"2026-10-17T22:18:50+0000: [libs]: Unable to determine path for file descriptor 13'
        with tempfile.TemporaryDirectory() as d:
            p = Path(d, 'falco.jsonl'); p.write_text('\n'.join([good, corrupt, good]), encoding='utf-8')
            with self.assertRaisesRegex(ValueError, r'falco\.jsonl:2'): list(read_jsonl(p))
            import contextlib, io
            err = io.StringIO()
            with contextlib.redirect_stderr(err): rows = list(read_jsonl(p, skip_invalid=True))
            self.assertEqual(len(rows), 2)
            self.assertIn('falco.jsonl:2: skipped unparseable line', err.getvalue())
            a = Path(d, 'audit.jsonl'); a.write_text(json.dumps(exec_event()), encoding='utf-8')
            for script in ('correlate.py', 'incidents.py', 'metrics.py', 'detection_coverage.py', 'report.py'):
                extra = ['--out', str(Path(d, 'r.html'))] if script == 'report.py' else []
                res = subprocess.run([sys.executable, str(ROOT / 'correlator' / script), '--audit', str(a), '--falco', str(p), *extra], capture_output=True, text=True)
                self.assertEqual(res.returncode, 0, f'{script}: {res.stderr}')
                self.assertIn('skipped unparseable line', res.stderr, script)

    def test_corrupt_audit_line_is_still_fatal(self):
        with tempfile.TemporaryDirectory() as d:
            a = Path(d, 'audit.jsonl'); a.write_text('{broken', encoding='utf-8')
            f = Path(d, 'falco.jsonl'); f.write_text(json.dumps(shell_alert()), encoding='utf-8')
            res = subprocess.run([sys.executable, str(ROOT / 'correlator' / 'correlate.py'), '--audit', str(a), '--falco', str(f)], capture_output=True, text=True)
            self.assertEqual(res.returncode, 2)

    def test_bundled_examples_correlate(self):
        res = subprocess.run([sys.executable, str(ROOT / 'correlator' / 'correlate.py'),
                              '--audit', str(ROOT / 'examples' / 'audit.jsonl'), '--falco', str(ROOT / 'examples' / 'falco.jsonl')],
                             capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertEqual(len(res.stdout.strip().splitlines()), 1)


if __name__ == '__main__':
    unittest.main()
