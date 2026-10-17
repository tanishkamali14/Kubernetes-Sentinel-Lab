$ErrorActionPreference = 'Stop'
Set-Location (Split-Path -Parent $PSScriptRoot)
foreach ($tool in @('docker','kind','kubectl','helm','python')) {
    if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) { throw "Required command not found: $tool" }
}
# Windows PowerShell 5.1 turns redirected native stderr into a terminating error under 'Stop'.
$ErrorActionPreference = 'Continue'
docker info *> $null
$dockerExit = $LASTEXITCODE
$ErrorActionPreference = 'Stop'
if ($dockerExit -ne 0) { throw 'Docker is not running. Start Docker Desktop with Linux containers.' }
$clusters = kind get clusters
if ($clusters -notcontains 'runtime-security') {
    kind create cluster --config kind/kind-config.yaml --wait 180s
    if ($LASTEXITCODE -ne 0) { throw 'Kind cluster creation failed.' }
} else { kubectl config use-context kind-runtime-security }
helm repo add kyverno https://kyverno.github.io/kyverno/ --force-update
helm repo add falcosecurity https://falcosecurity.github.io/charts --force-update
helm repo update
# Chart versions the lab was checked against (Kyverno 1.19.1, Falco 0.45.0); override via environment.
$kyvernoVersion = if ($env:KYVERNO_CHART_VERSION) { $env:KYVERNO_CHART_VERSION } else { '3.9.1' }
$falcoVersion = if ($env:FALCO_CHART_VERSION) { $env:FALCO_CHART_VERSION } else { '9.2.0' }
helm upgrade --install kyverno kyverno/kyverno --version $kyvernoVersion --namespace kyverno --create-namespace --wait --timeout 8m
if ($LASTEXITCODE -ne 0) { throw 'Kyverno installation failed.' }
kubectl apply -f kyverno/baseline-policies.yaml -f kyverno/advanced-policies.yaml
if ($LASTEXITCODE -ne 0) { throw 'Applying Kyverno policies failed.' }
helm upgrade --install falco falcosecurity/falco --version $falcoVersion --namespace falco --create-namespace --set driver.kind=modern_ebpf --set tty=true --values helm/falco-values.yaml --wait --timeout 10m
if ($LASTEXITCODE -ne 0) { throw 'Falco install failed. Check host kernel support and driver logs.' }
# helm --wait does not wait for a DaemonSet on a one-node cluster (maxUnavailable 1 counts zero ready pods
# as ready), so scenarios run right after install can start before Falco captures anything. Wait explicitly.
kubectl rollout status daemonset/falco -n falco --timeout=300s
if ($LASTEXITCODE -ne 0) { throw 'The Falco DaemonSet did not become ready.' }
Write-Host 'Waiting for Falco to open its syscall source...'
$ErrorActionPreference = 'Continue'
$capturing = $false
for ($i = 0; $i -lt 60 -and -not $capturing; $i++) {
    $log = kubectl logs -n falco daemonset/falco -c falco 2>$null
    if ($log -match "Opening 'syscall' source") { $capturing = $true } else { Start-Sleep -Seconds 2 }
}
$ErrorActionPreference = 'Stop'
if (-not $capturing) { throw 'Falco never opened its syscall source. Check: kubectl logs -n falco daemonset/falco -c falco' }
Start-Sleep -Seconds 5  # let the probe attach before the first event
Write-Host 'Cluster, API audit logging, Kyverno policies, and Falco are installed.'
