#requires -Version 5.1
# Έλεγχος σύνταξης χωρίς να εκτελείται ο κύριος κώδικας.
$path = Join-Path $PSScriptRoot 'dwrean-debloat.ps1'
$tokens = $null
$errors = $null
$null = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$errors)
if ($errors.Count -gt 0) {
    Write-Host 'Εντοπίστηκαν συντακτικά προβλήματα:' -ForegroundColor Red
    $errors | ForEach-Object { Write-Host $_.Message -ForegroundColor Red }
    exit 1
}
Write-Host 'Ο συντακτικός έλεγχος PowerShell ολοκληρώθηκε χωρίς σφάλματα.' -ForegroundColor Green
