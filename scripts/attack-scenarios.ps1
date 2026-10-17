$ErrorActionPreference = 'Stop'
Set-Location (Split-Path -Parent $PSScriptRoot)
New-Item -ItemType Directory -Force -Path runtime-data | Out-Null
$spec = Get-Content -Raw -LiteralPath scenarios/scenarios.json | ConvertFrom-Json
$runLog = Join-Path (Get-Location) 'runtime-data/scenario-run.jsonl'
if (Test-Path -LiteralPath $runLog) { Remove-Item -LiteralPath $runLog }
$ns = $spec.workload.namespace
$pod = $spec.workload.pod
$utf8 = New-Object System.Text.UTF8Encoding $false

function Get-Stamp { [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffZ') }
function Write-Run($id, $started, $result) {
    # AppendAllText keeps the log BOM-free; Add-Content -Encoding utf8 can add a BOM mid-file on 5.1.
    $line = ([ordered]@{ id = $id; started = $started; finished = (Get-Stamp); result = $result } | ConvertTo-Json -Compress)
    [System.IO.File]::AppendAllText($runLog, $line + "`n", $utf8)
}

$failures = @()
foreach ($s in $spec.scenarios) {
    $started = Get-Stamp
    Write-Host "[$($s.id)] $($s.title)"
    # Redirected native stderr is a terminating error under 'Stop' on Windows PowerShell 5.1, and
    # rejection (admission) or a denied read (runtime) is the expected path, so relax it per call.
    $manifest = $s.manifest
    $command = $s.command
    $ErrorActionPreference = 'Continue'
    if ($s.kind -eq 'admission') {
        kubectl apply -f $manifest 2>&1 | ForEach-Object { "$_" }
    } else {
        kubectl exec -n $ns $pod -- sh -c $command 2>&1 | ForEach-Object { "$_" }
    }
    $exit = $LASTEXITCODE
    $ErrorActionPreference = 'Stop'
    if ($s.kind -eq 'admission') {
        $result = if ($exit -eq 0) { 'admitted' } else { 'rejected' }
        if ($exit -eq 0) { $failures += "$($s.id): $manifest was unexpectedly admitted" }
    } else {
        $result = if ($exit -eq 0) { 'ok' } else { 'nonzero' }
        if ($exit -ne 0) { Write-Warning "[$($s.id)] command returned non-zero; the attempted syscall may still generate an alert." }
    }
    Write-Run $s.id $started $result
}
if ($failures.Count) { throw ("Policy failure:`n" + ($failures -join "`n")) }
Write-Host 'Wait several seconds for Falco output to flush, then run collect-and-correlate.ps1.'
