# Loads every falco/*.yaml on top of the default ruleset with `falco -V`; no cluster or kernel driver needed.
$ErrorActionPreference = 'Stop'
Set-Location (Split-Path -Parent $PSScriptRoot)
$image = if ($env:FALCO_IMAGE) { $env:FALCO_IMAGE } else { 'falcosecurity/falco:0.45.0' }
$validate = @('-V', '/etc/falco/falco_rules.yaml')
foreach ($f in Get-ChildItem falco -Filter *.yaml) { $validate += @('-V', "/rules/$($f.Name)") }
# Windows PowerShell 5.1 turns redirected native stderr into a terminating error under 'Stop'.
$ErrorActionPreference = 'Continue'
docker run --rm --entrypoint /usr/bin/falco -v "$((Get-Location).Path)/falco:/rules:ro" $image @validate 2>&1 | ForEach-Object { "$_" }
$exit = $LASTEXITCODE
$ErrorActionPreference = 'Stop'
if ($exit -ne 0) { throw 'Falco rule validation failed.' }
