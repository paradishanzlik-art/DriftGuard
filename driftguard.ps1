param([Parameter(ValueFromRemainingArguments=$true)][string[]]$Args)
python (Join-Path $PSScriptRoot "driftguard.py") @Args
exit $LASTEXITCODE
