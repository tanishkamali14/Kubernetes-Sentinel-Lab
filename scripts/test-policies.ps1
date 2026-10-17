# Runs the Kyverno CLI unit tests in kyverno/tests against both policy files; no cluster needed.
$ErrorActionPreference = 'Stop'
Set-Location (Split-Path -Parent $PSScriptRoot)
$image = if ($env:KYVERNO_CLI_IMAGE) { $env:KYVERNO_CLI_IMAGE } else { 'ghcr.io/kyverno/kyverno-cli:v1.19.1' }
if (Get-Command kyverno -ErrorAction SilentlyContinue) {
    kyverno test kyverno/tests
} else {
    docker run --rm -v "$((Get-Location).Path):/work:ro" -w /work $image test kyverno/tests
}
if ($LASTEXITCODE -ne 0) { throw 'Kyverno policy tests failed.' }
