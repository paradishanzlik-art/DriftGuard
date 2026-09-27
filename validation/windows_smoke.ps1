param(
    [string]$ProjectRoot = ".",
    [string]$OutputPath = ""
)

$ErrorActionPreference = "Stop"
$root = (Resolve-Path $ProjectRoot).Path
if (-not $OutputPath) {
    $OutputPath = Join-Path $root "validation\windows-validation-result.json"
}

function Invoke-Captured {
    param(
        [string]$Exe,
        [string[]]$Args,
        [string]$WorkingDirectory
    )
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    Push-Location $WorkingDirectory
    try {
        $text = (& $Exe @Args 2>&1 | Out-String)
        $exit = $LASTEXITCODE
    }
    finally {
        Pop-Location
        $sw.Stop()
    }
    [pscustomobject]@{
        exe = $Exe
        args = $Args
        exit_code = $exit
        seconds = [math]::Round($sw.Elapsed.TotalSeconds, 4)
        output = $text
    }
}

function Require-Success {
    param([object]$Result, [string]$Stage)
    if ($Result.exit_code -ne 0) {
        throw ($Stage + " failed with exit " + $Result.exit_code + ":" + [Environment]::NewLine + $Result.output)
    }
}

$venv = Join-Path $env:TEMP ("driftguard-win-venv-" + [guid]::NewGuid().ToString("N"))
$tmp = Join-Path $env:TEMP ("driftguard-win-fixture-" + [guid]::NewGuid().ToString("N"))

$pyLauncher = Get-Command py -ErrorAction SilentlyContinue
if ($pyLauncher) {
    & py -3 -m venv $venv
}
elseif (Get-Command python -ErrorAction SilentlyContinue) {
    & python -m venv $venv
}
else {
    throw "Python 3 was not found on PATH."
}
if ($LASTEXITCODE -ne 0) { throw "Failed to create validation virtual environment." }

$py = Join-Path $venv "Scripts\python.exe"
$dg = Join-Path $venv "Scripts\driftguard.exe"

$install = Invoke-Captured $py @("-m","pip","install","--no-build-isolation",$root) $root
if ($install.exit_code -ne 0) {
    $install = Invoke-Captured $py @("-m","pip","install",$root) $root
}
Require-Success $install "Fresh source install"

$tests = Invoke-Captured $py @("-m","unittest","discover","-s",(Join-Path $root "tests"),"-v") $root
Require-Success $tests "DriftGuard regression suite"

New-Item -ItemType Directory -Path (Join-Path $tmp "src") -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $tmp "tests") -Force | Out-Null

@"
[project]
name = "fixture"
version = "0.0.0"
requires-python = ">=3.9"
"@ | Set-Content -Path (Join-Path $tmp "pyproject.toml") -Encoding UTF8

@"
def value():
    return 1
"@ | Set-Content -Path (Join-Path $tmp "src\app.py") -Encoding UTF8

@"
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import app

class T(unittest.TestCase):
    def test_value(self):
        self.assertEqual(app.value(), 1)
"@ | Set-Content -Path (Join-Path $tmp "tests\test_app.py") -Encoding UTF8

$init = Invoke-Captured $dg @("--root",$tmp,"init") $tmp
Require-Success $init "Fixture baseline"

$cleanImpactRun = Invoke-Captured $dg @("--root",$tmp,"impact","--json") $tmp
Require-Success $cleanImpactRun "Clean impact"
$cleanImpact = $cleanImpactRun.output | ConvertFrom-Json

Add-Content -Path (Join-Path $tmp "src\app.py") -Value "# harmless Windows validation edit" -Encoding UTF8
$harmlessImpactRun = Invoke-Captured $dg @("--root",$tmp,"impact","--json") $tmp
Require-Success $harmlessImpactRun "Harmless impact"
$harmlessImpact = $harmlessImpactRun.output | ConvertFrom-Json
$harmlessNextRun = Invoke-Captured $dg @("--root",$tmp,"validate-next","--json") $tmp
Require-Success $harmlessNextRun "Harmless validate-next"
$harmlessNext = $harmlessNextRun.output | ConvertFrom-Json
$harmlessGuard = Invoke-Captured $dg @("--root",$tmp,"guard","--capture","--force","--",$py,"-m","unittest","discover","-s",(Join-Path $tmp "tests"),"-v") $tmp
Require-Success $harmlessGuard "Harmless guarded validation"

@"
def value()
    return 1
"@ | Set-Content -Path (Join-Path $tmp "src\app.py") -Encoding UTF8

$breakingImpactRun = Invoke-Captured $dg @("--root",$tmp,"impact","--json") $tmp
Require-Success $breakingImpactRun "Breaking impact"
$breakingImpact = $breakingImpactRun.output | ConvertFrom-Json
$breakingNextRun = Invoke-Captured $dg @("--root",$tmp,"validate-next","--json") $tmp
Require-Success $breakingNextRun "Breaking validate-next"
$breakingNext = $breakingNextRun.output | ConvertFrom-Json
$breakingGuard = Invoke-Captured $dg @("--root",$tmp,"guard","--capture","--force","--",$py,"-m","unittest","discover","-s",(Join-Path $tmp "tests"),"-v") $tmp
if ($breakingGuard.exit_code -eq 0) {
    throw "Breaking guarded validation unexpectedly passed."
}

$incidentRun = Invoke-Captured $dg @("--root",$tmp,"incidents","--limit","1","--json") $tmp
Require-Success $incidentRun "Incident retrieval"
$incidents = $incidentRun.output | ConvertFrom-Json
$incident = @($incidents)[-1]
$signature = $incident.primary_signature

$result = [ordered]@{
    schema = 1
    code_commit = "47bc7af2e613e33e44d6181359e3137ae0c74793"
    generated_at = (Get-Date).ToUniversalTime().ToString("o")
    os = [System.Environment]::OSVersion.VersionString
    powershell = $PSVersionTable.PSVersion.ToString()
    python = (& $py --version 2>&1 | Out-String).Trim()
    driftguard_py_sha256 = (Get-FileHash (Join-Path $root "driftguard.py") -Algorithm SHA256).Hash.ToLowerInvariant()
    regression_suite_exit = $tests.exit_code
    clean_source_changes = $cleanImpact.total_changes
    harmless_source_changes = $harmlessImpact.total_changes
    harmless_component = @($harmlessImpact.changed_components)
    harmless_validation = $harmlessNext.command
    harmless_guard_exit = $harmlessGuard.exit_code
    breaking_source_changes = $breakingImpact.total_changes
    breaking_component = @($breakingImpact.changed_components)
    breaking_validation = $breakingNext.command
    breaking_guard_exit = $breakingGuard.exit_code
    breaking_signature = $signature
    expected_signature = "python.syntax"
    passed = (
        $tests.exit_code -eq 0 -and
        $cleanImpact.total_changes -eq 0 -and
        $harmlessImpact.total_changes -ge 1 -and
        $harmlessGuard.exit_code -eq 0 -and
        $breakingImpact.total_changes -ge 1 -and
        $breakingGuard.exit_code -ne 0 -and
        $signature -eq "python.syntax"
    )
    timings_seconds = [ordered]@{
        install = $install.seconds
        regression_suite = $tests.seconds
        harmless_guard = $harmlessGuard.seconds
        breaking_guard = $breakingGuard.seconds
    }
    fixture_path = $tmp
}

$result | ConvertTo-Json -Depth 8 | Set-Content -Path $OutputPath -Encoding UTF8
$result | ConvertTo-Json -Depth 8
if (-not $result.passed) { exit 1 }
