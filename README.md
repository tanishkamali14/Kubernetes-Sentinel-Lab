# Kubernetes Sentinel Lab

A local Kubernetes sentinel lab combining admission prevention, syscall detection, API audit logging, event correlation into scored incidents, scenario-based detection coverage, and an HTML report.

## Architecture

```text
kubectl request ──> Kubernetes API audit log ───────────────┐
                      └── Kyverno denies unsafe Pods        │
container syscalls ──> Falco JSON alert ────────────────────┤
                                                            v
 attack-scenarios ──> scenario-run.jsonl ──> collect-and-correlate ──> JSONL
                                                            │
        ┌───────────────┬──────────────────┬────────────────┴──┐
        v               v                  v                   v
  correlate.py     incidents.py   detection_coverage.py     report.py
  exec ↔ shell    scored per-pod   did each scenario      self-contained
  matches         incidents,       produce its expected   HTML report
                  ATT&CK mapping   denial / alert?
```

## Requirements

- Windows 10/11 with Docker Desktop running Linux containers, or Linux with Docker Engine.
- `kind`, `kubectl`, and Helm 3 on `PATH`.
- Python 3.10+ (standard library only).
- Internet access for chart and container image downloads.

Install Kind on Windows with `winget install Kubernetes.kind` (open a new terminal afterwards so it is on `PATH`), and start Docker Desktop before running `up.ps1`.

Kind and Docker Desktop are used for the included audit log configuration. Falco's syscall driver needs host kernel support. Docker Desktop's WSL2 backend may behave differently from a Linux host; if the Falco DaemonSet cannot load its driver, use a Linux VM or host with a supported kernel. This repo does not assume that a successful Helm install means syscall capture is active.

## Quick start (PowerShell)

From this directory:

```powershell
.\scripts\up.ps1
.\scripts\deploy-workload.ps1
.\scripts\attack-scenarios.ps1
.\scripts\collect-and-correlate.ps1
```

`up.ps1` creates the `runtime-security` Kind cluster with API audit logging, installs Kyverno and Falco from pinned chart versions, and applies both Kyverno policy tiers. The cluster create is skipped if that Kind cluster already exists. The audit log file is retained in the Kind control-plane container; collection writes snapshots, `falco-raw.log` and `report.html` to `runtime-data/`.

`attack-scenarios.ps1` runs every scenario in `scenarios/scenarios.json` (four admission attempts that must be rejected, four runtime actions inside the sample Pod) and records when each one ran. `collect-and-correlate.ps1` prints the correlation, metrics, incidents and coverage tables and writes `runtime-data/report.html`; add `-FailOnGap` to make it fail when a scenario did not produce its expected signal.

Run individual controls:

```powershell
kubectl apply -f examples/denied-privileged.yaml
kubectl apply -f examples/denied-hostpath.yaml
kubectl apply -f examples/denied-nonroot.yaml
kubectl apply -f examples/denied-capabilities.yaml
```

Each invalid Pod should be rejected by Kyverno. The valid sample should be accepted. Falco alerts are written to pod logs as JSON.

## Linux shell alternative

Every PowerShell script has a Bash twin (`up.sh`, `deploy-workload.sh`, `attack-scenarios.sh`, `collect-and-correlate.sh [--fail-on-gap]`), and the `Makefile` wraps them:

```bash
make up deploy attack collect
```

Manually: `kind create cluster --name runtime-security --config kind/kind-config.yaml`, collect the audit log with `docker exec runtime-security-control-plane cat /var/log/kubernetes/kube-apiserver-audit.log`, and Falco JSON with `kubectl logs -n falco -l app.kubernetes.io/name=falco --all-containers=true`.

## Detection content

### Falco rules (`falco/`)

Every rule carries a MITRE ATT&CK technique tag (`T1234[.567]`) that the correlator reads. Rule output includes `namespace=%k8s.ns.name pod=%k8s.pod.name`, which the correlator needs to join alerts to API audit events.

| Rule | Technique | Priority |
| --- | --- | --- |
| Detect shell in container | T1059.004 Unix Shell | Warning |
| Detect read of shadow file in container | T1003.008 /etc/passwd and /etc/shadow | Warning |
| Detect service account token access in container | T1552.007 Container API | Warning |
| Detect package manager in container | T1105 Ingress Tool Transfer | Notice |
| Detect download tool in container | T1105 Ingress Tool Transfer | Notice |
| Detect network tool in container | T1095 Non-Application Layer Protocol | Warning |
| Detect network scanner in container | T1046 Network Service Discovery | Warning |
| Detect Kubernetes client in container | T1613 Container and Resource Discovery | Warning |
| Detect cryptominer process in container | T1496 Resource Hijacking | Critical |

`falco/*.yaml` is the source. `helm/falco-values.yaml` is generated from it; after editing a rule run:

```powershell
python scripts\sync_falco_values.py
```

The shadow-file and token rules match the `open()` attempt (`evt.arg.name`) instead of the shipped `open_read` macro, because that macro requires a successful open and the non-root sample Pod is denied `/etc/shadow` with `EACCES`. The service account token rule will also fire for legitimate Kubernetes clients; tune it before using it elsewhere. Rules use the shipped Falco macros `spawned_process` and `container`. Confirm the Falco pod is healthy, the driver loads, and rule files report no errors before trusting the detection result.

### Kyverno policies (`kyverno/`)

| Policy | Mode | Blocks |
| --- | --- | --- |
| `disallow-privileged-containers` | Enforce | `privileged: true` in containers, init containers, or ephemeral containers |
| `disallow-hostpath-volumes` | Enforce | any `hostPath` volume |
| `require-nonroot` | Enforce | missing `runAsNonRoot: true` at Pod and container level |
| `require-drop-all-capabilities` | Enforce | containers and init containers that do not drop `ALL` |
| `disallow-host-namespaces` | Enforce | `hostNetwork`, `hostPID`, `hostIPC` |
| `disallow-privilege-escalation` | Enforce | `allowPrivilegeEscalation` not set to `false` |
| `disallow-latest-tag` | Enforce | untagged images and the `latest` tag |
| `require-resource-limits` | Audit | missing CPU or memory limits (see `kubectl get policyreport -A`) |

The first four are `baseline-policies.yaml`; the rest are `advanced-policies.yaml`. The `falco`, `kube-system`, and `local-path-storage` namespaces are excluded in every rule: the Falco DaemonSet is privileged, mounts `hostPath` volumes, and runs as root by design, and Kyverno's autogen would otherwise reject it. This is a lab baseline. Review workload compatibility, namespaces, exceptions, and security requirements before production use. Kyverno's own namespace is excluded by its chart defaults.

The policies match `Pod`, not the `pods/ephemeralcontainers` subresource, so the ephemeral-container check applies to Pods that already carry `ephemeralContainers` in the spec, not to `kubectl debug` added later.

## Correlation, incidents, and metrics

To inspect the included example records without a cluster:

```powershell
python .\correlator\correlate.py --audit .\examples\audit.jsonl --falco .\examples\falco.jsonl
python .\correlator\metrics.py --audit .\examples\audit.jsonl --falco .\examples\falco.jsonl
```

`examples/advanced/` is a larger simulated run: Kyverno denials, a chained exec-to-credential-access sequence, a shell with no audit trail, a cryptominer, and one deliberate coverage gap (scenario A4).

```powershell
cd examples\advanced
python ..\..\correlator\incidents.py --audit audit.jsonl --falco falco.jsonl --format table
python ..\..\correlator\detection_coverage.py --audit audit.jsonl --falco falco.jsonl --run scenario-run.jsonl --format table
python ..\..\correlator\report.py --audit audit.jsonl --falco falco.jsonl --run scenario-run.jsonl --out report.html
```

`correlate.py` joins shell alerts to the closest `pods/exec` audit event with the same namespace and Pod within the time window (`--window-seconds`, default 30). It emits one JSON object per match. This is temporal correlation, not proof of causation, so do not automate containment from this output alone.

`incidents.py` goes further: it groups every audit and Falco signal per Pod, closes an incident after `--gap-seconds` (default 120) of silence, and emits one incident per run with a timeline, actors, ATT&CK techniques, and a triage score. Formats: `jsonl` (default), `json`, `table`; filter with `--min-severity`.

| Score component | Points |
| --- | --- |
| each distinct Falco rule, by priority (critical 40, error 30, warning 15, notice 5, info 2) | per rule, once |
| `kubectl exec` followed by runtime alerts in the same incident | +15 |
| a shell alert with no matching `pods/exec` audit event | +20 |
| `kubectl exec` plus a credential-access alert | +10 |
| admission denial (+5 per extra blocking policy) | +10 |

The total is capped at 100: critical ≥ 70, high ≥ 40, medium ≥ 20, otherwise low. Two blind-spot findings are reported per incident: `shell_without_exec_audit` (a shell that did not come through the API server, such as application-level code execution) and `exec_without_falco_alert` (an exec that raised no runtime alert, so verify Falco coverage). The score is a heuristic for ordering work, not a verdict.

Not every non-2xx audit record is a refusal. `404`, `409` and `410` (not found, conflict, gone) are ordinary API races, and the kubelet's own control-plane mirror-pod refusals in `kube-system` at node start are ignored, so a fresh cluster does not open incidents for itself.

Falco input is read tolerantly: container logs can splice a Falco log message into the middle of an alert line, so a line that is not valid JSON is skipped with a `warning: <file>:<line>` on stderr instead of aborting. The audit log is still strict.

`metrics.py` summarizes audit exec requests (de-duplicated, since exec is logged at two stages), denied API responses and denials by Kyverno policy, Falco alerts by rule, correlated matches, shell alerts without an exec audit event, incidents by severity, and ATT&CK techniques observed. Denials are inferred from non-2xx audit `responseStatus.code`; they include any denied API operation, not only policy denials. Policy names are parsed from Kyverno's denial message.

## Scenario coverage

`scenarios/scenarios.json` is the single list of attacks: the runners execute it and `detection_coverage.py` checks it. Each scenario states what it expects: an admission denial by a named policy, a named Falco rule firing for the sample Pod, or a `pods/exec` audit event.

| ID | Scenario | Expected signal |
| --- | --- | --- |
| A1-A4 | privileged, hostPath, root, and capability-retaining Pods | denial by the matching policy |
| R1 | shell through `kubectl exec` | exec audit event and shell alert |
| R2 | `cat /etc/shadow` | shadow-file alert |
| R3 | read the service account token | token alert |
| R4 | `apt-get --version` | package-manager alert |

The runners write `runtime-data/scenario-run.jsonl` with each scenario's start and end time. With `--run`, each expectation must be observed inside that scenario's window (plus `--settle-seconds`, default 15), so an alert left from an earlier run cannot satisfy a later scenario. Coverage here means the expected signal appeared in the collected data for this lab's scenarios; it is not a measure of detection against real attackers.

To add a scenario, add a Falco rule if needed (then run `sync_falco_values.py`), add an entry to `scenarios.json` (runtime commands must not contain double quotes; Windows PowerShell 5.1 mangles them), and run the tests. They check that every referenced manifest, policy, rule, and technique tag exists.

## Validation tooling

| Command | Needs | Checks |
| --- | --- | --- |
| `python -m unittest discover -s tests -v` | Python only | correlation, incidents, coverage, report, and static consistency of every config file |
| `.\scripts\test-policies.ps1` | Docker or the `kyverno` binary | Kyverno CLI unit tests: `kyverno/tests` has a passing and a failing Pod for every policy rule, plus an excluded-namespace case |
| `.\scripts\validate-falco-rules.ps1` | Docker | loads `falco/*.yaml` over the default ruleset with `falco -V` |
| `python scripts\sync_falco_values.py --check` | Python only | `helm/falco-values.yaml` matches `falco/*.yaml` |

The unit tests do not prove that Kyverno rejects the example Pods or that Falco captures syscalls in your environment; that needs a running cluster (`up.ps1`, then `attack-scenarios.ps1` and `collect-and-correlate.ps1 -FailOnGap`).

`.github/workflows/ci.yml` runs the unit tests (Python 3.10 and 3.13), the sync check, the Kyverno policy tests and the Falco rule validation on every push and pull request, and the full Kind lab nightly, on pushes to `main`, and on demand.

## Verification status

Confirmed in CI (GitHub Actions, Ubuntu 24.04 runner, Kind v0.31, Kubernetes 1.35, Kyverno 1.19.1, Falco 0.45.0 with the modern eBPF probe). The end-to-end job runs the whole lab (`up.sh`, `deploy-workload.sh`, `attack-scenarios.sh`, `collect-and-correlate.sh --fail-on-gap`) and passes:

- **Prevention:** the four admission scenarios (A1-A4) are denied by Kyverno, recorded in the API audit log, and the blocking policy names are parsed from the denial message.
- **Detection:** the four runtime scenarios (R1-R4) each raise their expected Falco alert (shell, shadow-file attempt with `EACCES`, service account token, package manager), so coverage is 8 of 8.
- **Correlation:** each `kubectl exec` is joined to the shell alert it caused, about 50 ms apart and attributed to the calling user, and the run produces five incidents (one critical for `runtime-lab`, four for the denied Pods).
- **Static checks:** the 21 Kyverno CLI policy tests and the Falco rule validation pass.

Falco's default ruleset also fires on Kind's own node activity during startup (for example "Drop and execute new binary in container"). Those alerts appear in the Falco counts but carry no pod context, so they open no incidents.

Not covered by CI: Windows with Docker Desktop. The lab has not been run on Docker Desktop's WSL2 backend, where Falco's modern eBPF probe depends on the WSL2 kernel (see Requirements). If it does not work there, run the lab on a Linux host or VM, which is what CI does. Falco's own startup lines (not JSON) are the quickest way to tell: `kubectl logs -n falco daemonset/falco -c falco`.

When the coverage gate fails, `collect-and-correlate` has saved `runtime-data/falco-raw.log` (every Falco pod container) and the CI job prints Falco's pod state and logs, so you can tell whether Falco captured nothing or the alerts were lost on the way out.

Kyverno 1.19 prints a deprecation warning for `kyverno.io/v1` `ClusterPolicy` (it points to `ValidatingPolicy` and the other `policies.kyverno.io` types). The policies here still work on 1.19.1; migrate them before moving to a release that removes the legacy types.

## Pinned versions

`up.ps1` and `up.sh` install Kyverno chart 3.9.1 (Kyverno 1.19.1) and Falco chart 9.2.0 (Falco 0.45.0), the versions whose values and CRDs this repo was checked against. Override with `KYVERNO_CHART_VERSION` and `FALCO_CHART_VERSION`. The policy test and rule validation images are pinned in the scripts (`KYVERNO_CLI_IMAGE`, `FALCO_IMAGE`).

## Falco configuration

Falco is installed from the official Helm chart with `modern_ebpf`, JSON output, and `helm/falco-values.yaml`. The libs logger is limited to errors so its warnings do not share the log stream with alerts. `up.ps1` and `up.sh` wait until the Falco DaemonSet is rolled out and has opened its syscall source before returning; `helm --wait` alone does not, because on a one-node cluster the default `maxUnavailable` of 1 counts zero ready pods as ready, and scenarios run straight after install would start before Falco captures anything.

## API audit configuration

The API server audit policy logs metadata for Pod create/update/patch/delete and for `pods/exec`, `pods/attach`, and `pods/portforward` regardless of verb (SPDY exec is audited as `create`, WebSocket exec may be audited as `get`). Kind mounts `audit/policy.yaml` into its control plane and writes the log to `/var/log/kubernetes/kube-apiserver-audit.log`. This policy is for a local lab; audit policy and storage settings for managed clusters are provider-specific.

## Teardown

```powershell
kind delete cluster --name runtime-security
```

The teardown removes the local cluster. Project files and collected snapshots remain in this folder.

## References

- [Kind auditing](https://kind.sigs.k8s.io/docs/user/auditing/)
- [Falco Kubernetes deployment](https://falco.org/docs/getting-started/deployment/)
- [Falco custom rules](https://falco.org/docs/concepts/rules/custom-ruleset/)
- [Kyverno installation](https://kyverno.io/docs/installation/installation/)
- [Kyverno validation policies](https://kyverno.io/docs/policy-types/cluster-policy/validate/)
- [Kyverno CLI test](https://kyverno.io/docs/kyverno-cli/reference/kyverno_test/)
- [MITRE ATT&CK for Containers](https://attack.mitre.org/matrices/enterprise/containers/)
