$ErrorActionPreference = 'Stop'
Set-Location (Split-Path -Parent $PSScriptRoot)
kubectl apply -f examples/workload.yaml
if ($LASTEXITCODE -ne 0) { throw 'Applying workload failed.' }
kubectl wait --for=condition=Ready pod/runtime-lab --timeout=180s
if ($LASTEXITCODE -ne 0) { throw 'Workload did not become Ready.' }
Write-Host 'runtime-lab is ready.'
