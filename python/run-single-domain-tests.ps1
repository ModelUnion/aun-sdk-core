$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
$dataRoot = Join-Path $repoRoot '..\docker-deploy\data\sdk-tester-aun'
$persistentRoot = Join-Path $dataRoot 'single-domain\persistent'

$env:AUN_ENV = 'development'
$env:AUN_DATA_ROOT = [System.IO.Path]::GetFullPath($dataRoot)
$env:AUN_TEST_AUN_PATH = [System.IO.Path]::GetFullPath($persistentRoot)

Write-Host "AUN_ENV=$env:AUN_ENV"
Write-Host "AUN_DATA_ROOT=$env:AUN_DATA_ROOT"
Write-Host "AUN_TEST_AUN_PATH=$env:AUN_TEST_AUN_PATH"

Push-Location $PSScriptRoot
try {
    python -X utf8 tests/integration_test_e2ee.py
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    python -X utf8 tests/e2e_test_group_e2ee.py
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
} finally {
    Pop-Location
}
