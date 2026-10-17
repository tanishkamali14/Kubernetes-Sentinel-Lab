"""Static checks on the lab configuration that need no cluster and no third-party packages."""
import importlib.util
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
POLICY_FILES = ('kyverno/baseline-policies.yaml', 'kyverno/advanced-policies.yaml')
EXCLUDED = 'namespaces: [falco, kube-system, local-path-storage]'


def read(rel):
    return (ROOT / rel).read_text(encoding='utf-8')


def policy_rules():
    """Map (policy, rule) -> failureAction using the files' fixed layout, so no YAML library is needed."""
    out = {}
    for rel in POLICY_FILES:
        for doc in read(rel).split('\n---\n'):
            policy = re.search(r'^  name: (\S+)', doc, flags=re.M)
            if not policy: continue
            for chunk in re.split(r'^    - name: ', doc, flags=re.M)[1:]:
                out[(policy.group(1), chunk.split('\n', 1)[0].strip())] = (re.search(r'failureAction: (\w+)', chunk) or [None, None])[1]
                assert EXCLUDED in chunk, f'{policy.group(1)} rule {chunk.splitlines()[0]} lacks the namespace exclusion'
    return out


class FalcoTests(unittest.TestCase):
    def test_helm_values_are_generated_from_rule_files(self):
        spec = importlib.util.spec_from_file_location('sync_falco_values', ROOT / 'scripts' / 'sync_falco_values.py')
        mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
        self.assertEqual(mod.render(), read('helm/falco-values.yaml'), 'run scripts/sync_falco_values.py')

    def test_every_rule_has_priority_output_and_a_technique_tag(self):
        for f in (ROOT / 'falco').glob('*.yaml'):
            text = f.read_text(encoding='utf-8')
            blocks = re.split(r'^- rule: ', text, flags=re.M)[1:]
            self.assertTrue(blocks, f.name)
            for b in blocks:
                name = b.splitlines()[0]
                for key in ('desc:', 'condition:', 'output:', 'priority:', 'tags:'):
                    self.assertIn(key, b, f'{name} missing {key}')
                self.assertRegex(b, r'tags: \[[^\]]*\bT\d{4}(\.\d{3})?\b', f'{name} has no ATT&CK technique tag')
                self.assertIn('namespace=%k8s.ns.name pod=%k8s.pod.name', b, f'{name} output must carry namespace and pod for correlation')

    def test_rule_names_are_unique(self):
        names = [n for f in (ROOT / 'falco').glob('*.yaml') for n in re.findall(r'^- rule: (.+)$', f.read_text(encoding='utf-8'), flags=re.M)]
        self.assertEqual(len(names), len(set(names)))


class KyvernoTests(unittest.TestCase):
    def test_all_policies_enforce_except_resource_limits(self):
        actions = policy_rules()
        self.assertTrue(actions)
        for (policy, rule), action in actions.items():
            self.assertEqual(action, 'Audit' if policy == 'require-resource-limits' else 'Enforce', f'{policy}/{rule}')

    def test_policies_cover_readme_claims(self):
        text = ''.join(read(f) for f in POLICY_FILES)
        for needle in ('privileged', 'hostPath', 'runAsNonRoot', 'capabilities.drop', 'ephemeralContainers', 'initContainers',
                       'hostNetwork', 'allowPrivilegeEscalation', ':latest', 'limits'):
            self.assertIn(needle, text)

    def test_cli_tests_cover_every_rule_with_a_pass_and_a_fail(self):
        tests = read('kyverno/tests/kyverno-test.yaml')
        for (policy, rule) in policy_rules():
            for result in ('pass', 'fail'):
                pattern = rf'policy: {re.escape(policy)}\n\s+rule: {re.escape(rule)}\n\s+kind: Pod\n\s+resources: \[[^\]]+\]\n\s+result: {result}'
                self.assertRegex(tests, pattern, f'{policy}/{rule} has no {result} case')

    def test_cli_test_resources_exist(self):
        names = set(re.findall(r'^  name: (\S+)', read('kyverno/tests/resources.yaml'), flags=re.M))
        for pod in re.findall(r'resources: \[([^\]]+)\]', read('kyverno/tests/kyverno-test.yaml')):
            self.assertIn(pod.strip(), names)

    def test_denied_examples_violate_exactly_their_policy(self):
        self.assertIn('privileged: true', read('examples/denied-privileged.yaml'))
        self.assertIn('hostPath:', read('examples/denied-hostpath.yaml'))
        self.assertNotIn('runAsNonRoot', read('examples/denied-nonroot.yaml'))
        caps = read('examples/denied-capabilities.yaml')
        self.assertIn('add: [NET_ADMIN]', caps)
        self.assertNotIn('drop', caps)

    def test_workload_satisfies_every_policy(self):
        wl = read('examples/workload.yaml')
        for needle in ('runAsNonRoot: true', 'drop: [ALL]', 'allowPrivilegeEscalation: false', 'limits:', 'cpu:', 'memory:'):
            self.assertIn(needle, wl)
        for forbidden in ('hostPath', 'privileged: true', 'hostNetwork', ':latest'):
            self.assertNotIn(forbidden, wl)
        self.assertRegex(wl, r'image: \S+:[\w.-]+')


class ScriptTests(unittest.TestCase):
    def scripts(self):
        return sorted((ROOT / 'scripts').glob('*.ps1')) + sorted((ROOT / 'scripts').glob('*.sh'))

    def test_kind_config_mounts_the_audit_policy_it_references(self):
        cfg = read('kind/kind-config.yaml')
        self.assertIn('/etc/kubernetes/policies/audit-policy.yaml', cfg)
        self.assertIn('./audit/policy.yaml', cfg)
        self.assertTrue((ROOT / 'audit' / 'policy.yaml').is_file())

    def test_scripts_reference_existing_files(self):
        for script in self.scripts():
            # The lookbehind skips absolute paths such as /etc/falco/falco_rules.yaml, which live inside containers.
            for ref in re.findall(r'(?<![\w/.-])((?:kind|kyverno|helm|examples|correlator|scenarios|falco|scripts)/[\w./-]+\.(?:yaml|py|json|sh|ps1))', script.read_text(encoding='utf-8')):
                self.assertTrue((ROOT / ref).is_file(), f'{script.name} references missing {ref}')

    def test_every_ps1_has_a_bash_counterpart_where_documented(self):
        for stem in ('up', 'deploy-workload', 'attack-scenarios', 'collect-and-correlate', 'test-policies', 'validate-falco-rules'):
            self.assertTrue((ROOT / 'scripts' / f'{stem}.ps1').is_file(), stem)
            self.assertTrue((ROOT / 'scripts' / f'{stem}.sh').is_file(), stem)

    def test_shell_scripts_use_lf_line_endings(self):
        for f in [*self.scripts(), ROOT / 'Makefile']:
            if f.suffix in ('.sh', '') and f.name != 'Makefile' or f.name == 'Makefile':
                self.assertNotIn(b'\r\n', f.read_bytes(), f'{f.name} has CRLF line endings, which break bash')

    def test_ps1_stderr_redirects_are_guarded_for_windows_powershell_5_1(self):
        # Under $ErrorActionPreference = 'Stop', Windows PowerShell 5.1 throws on redirected native stderr.
        for f in (ROOT / 'scripts').glob('*.ps1'):
            mode = None  # the most recent $ErrorActionPreference assignment seen above the current line
            for i, line in enumerate(f.read_text(encoding='utf-8').splitlines(), 1):
                if m := re.search(r"\$ErrorActionPreference = '(\w+)'", line): mode = m.group(1)
                if re.search(r'2>&1|\*>\s*\$null', line) and not line.lstrip().startswith('#'):
                    self.assertNotEqual(mode, 'Stop', f'{f.name}:{i} redirects native stderr while $ErrorActionPreference is Stop')

    def test_up_waits_for_falco_to_capture_before_returning(self):
        # helm --wait returns immediately for a one-node DaemonSet, so scenarios used to run before Falco started.
        for script in ('up.ps1', 'up.sh'):
            text = read(f'scripts/{script}')
            self.assertIn('rollout status daemonset/falco', text, script)
            self.assertIn("Opening 'syscall' source", text, script)
            self.assertLess(text.index('rollout status daemonset/falco'), text.rindex('installed'), script)

    def test_falco_log_collection_is_not_truncated_or_mixed_with_sidecars(self):
        # kubectl logs -l defaults to --tail=10 per container, and falcoctl sidecars log JSON that is not alerts.
        for script in ('collect-and-correlate.ps1', 'collect-and-correlate.sh'):
            text = read(f'scripts/{script}')
            first = next(l for l in text.splitlines() if 'kubectl logs' in l and '-c falco' in l)
            self.assertIn('--tail=-1', first, script)
            self.assertIn('falco-raw.log', text, script)

    def test_chart_versions_are_pinned(self):
        for script in ('up.ps1', 'up.sh'):
            text = read(f'scripts/{script}')
            self.assertRegex(text, r'3\.\d+\.\d+')
            self.assertRegex(text, r'9\.\d+\.\d+')
            self.assertEqual(text.count('--version'), 2, script)


if __name__ == '__main__':
    unittest.main()
