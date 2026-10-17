param([switch]$FailOnGap)
$ErrorActionPreference = 'Stop'
Set-Location (Split-Path -Parent $PSScriptRoot)
New-Item -ItemType Directory -Force -Path runtime-data | Out-Null
docker exec runtime-security-control-plane cat /var/log/kubernetes/kube-apiserver-audit.log |
    Set-Content -LiteralPath runtime-data/audit.jsonl -Encoding utf8
if ($LASTEXITCODE -ne 0) { throw 'Could not read the Kind API audit log.' }
# Windows PowerShell 5.1 turns redirected native stderr into a terminating error under 'Stop'.
$ErrorActionPreference = 'Continue'
# With a label selector kubectl logs defaults to the last 10 lines per container, so ask for all of them,
# and read only the falco container: the falcoctl sidecars also log JSON lines that are not alerts.
$lines = kubectl logs -n falco -l app.kubernetes.io/name=falco -c falco --tail=-1 --since=24h 2>&1
$logsExit = $LASTEXITCODE
# Everything from every container, kept for diagnosing a Falco that raised no alerts (best effort).
kubectl logs -n falco -l app.kubernetes.io/name=falco --all-containers=true --prefix --tail=-1 --since=24h 2>&1 |
    ForEach-Object { "$_" } | Set-Content -LiteralPath runtime-data/falco-raw.log -Encoding utf8
$ErrorActionPreference = 'Stop'
if ($logsExit -ne 0) { throw 'Could not read Falco logs. Check the Falco DaemonSet.' }
$lines | Where-Object { $_ -match '^\s*\{' } | Set-Content -LiteralPath runtime-data/falco.jsonl -Encoding utf8
$a = @('--audit', 'runtime-data/audit.jsonl', '--falco', 'runtime-data/falco.jsonl')

Write-Host '--- exec/shell correlation'
python correlator/correlate.py @a --window-seconds 30
if ($LASTEXITCODE -ne 0) { throw 'Correlation failed; inspect collected JSONL files.' }
Write-Host '--- metrics'
python correlator/metrics.py @a --window-seconds 30
if ($LASTEXITCODE -ne 0) { throw 'Metrics generation failed.' }
Write-Host '--- incidents'
python correlator/incidents.py @a --format table
if ($LASTEXITCODE -ne 0) { throw 'Incident building failed.' }

$cov = @('correlator/detection_coverage.py') + $a + @('--format', 'table')
$report = @('correlator/report.py') + $a + @('--out', 'runtime-data/report.html')
if (Test-Path -LiteralPath runtime-data/scenario-run.jsonl) {
    $cov += @('--run', 'runtime-data/scenario-run.jsonl'); $report += @('--run', 'runtime-data/scenario-run.jsonl')
}
if ($FailOnGap) { $cov += '--fail-on-gap' }
python @report
if ($LASTEXITCODE -ne 0) { throw 'Report generation failed.' }
Write-Host '--- scenario coverage'
python @cov
if ($LASTEXITCODE -ne 0) { throw 'Scenario coverage check failed (a gap with -FailOnGap, or an unreadable input).' }
Write-Host 'Snapshots and report.html saved under runtime-data/.'
