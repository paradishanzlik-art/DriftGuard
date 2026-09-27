param(
    [string]$Python = "py",
    [string]$ProjectRoot = "."
)

$ErrorActionPreference = "Stop"
$root = (Resolve-Path $ProjectRoot).Path
$venv = Join-Path $root ".driftguard-windows-validation"
if (Test-Path $venv) { Remove-Item -Recurse -Force $venv }

& $Python -3 -m venv $venv
$py = Join-Path $venv "Scripts\python.exe"
$dg = Join-Path $venv "Scripts\driftguard.exe"

& $py -m pip install --no-build-isolation $root
& $py -m unittest discover -s (Join-Path $root "tests") -v

$tmp = Join-Path $env:TEMP ("driftguard-win-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path (Join-Path $tmp "src") -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $tmp "tests") -Force | Out-Null

@"
[project]
name = "fixture"
version = "0.0.0"
requires-python = ">=3.9"
"@ | Set-Content -Path (Join-Path $tmp "pyproject.toml")

Set-Content -Path (Join-Path $tmp "src\app.py") -Value "VALUE = 1"
@"
import unittest
class T(unittest.TestCase):
    def test_ok(self):
        self.assertTrue(True)
"@ | Set-Content -Path (Join-Path $tmp "tests\test_app.py")

& $dg --root $tmp init
& $dg --root $tmp impact --json
Add-Content -Path (Join-Path $tmp "src\app.py") -Value "# harmless change"
& $dg --root $tmp impact --json
& $dg --root $tmp validate-next --json
& $dg --root $tmp guard --capture --force -- $py -m unittest discover -s (Join-Path $tmp "tests") -v

Write-Host "Windows DriftGuard smoke validation completed."
Write-Host "Record Windows version, Python version, exits, and output before deleting $tmp."
