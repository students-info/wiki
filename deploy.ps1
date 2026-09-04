# Deploy script: encrypt content/ -> articles/, regenerate content-index.json,
# commit and push. Reads the password from .env (which is gitignored).
#
# Usage:
#   .\deploy.ps1 [commit message]
#
# Requires: Python 3 + cryptography, git, and a configured remote on branch main.

param(
    [string]$Message = "deploy: update wiki"
)

$ErrorActionPreference = "Stop"

# --- Load password from .env ---
if (-not (Test-Path -LiteralPath ".env")) {
    Write-Host "ERROR: .env not found. Copy .env.example to .env and set WIKI_PASSWORD." -ForegroundColor Red
    exit 1
}

$password = $null
Get-Content -LiteralPath ".env" | ForEach-Object {
    if ($_ -match '^\s*WIKI_PASSWORD\s*=\s*(.+?)\s*$') {
        $password = $matches[1]
    }
}

if (-not $password -or $password -eq "change-me") {
    Write-Host "ERROR: WIKI_PASSWORD is empty or still 'change-me' in .env." -ForegroundColor Red
    exit 1
}

# --- Check prerequisites ---
python --version *> $null
if (-not $?) {
    Write-Host "ERROR: python not found." -ForegroundColor Red
    exit 1
}
git --version *> $null
if (-not $?) {
    Write-Host "ERROR: git not found." -ForegroundColor Red
    exit 1
}

# --- Encrypt content/ -> articles/ and regenerate content-index.json ---
Write-Host "== Encrypting content/ -> articles/ ==" -ForegroundColor Cyan
python encrypt.py $password content articles
if (-not $?) {
    Write-Host "ERROR: encryption failed." -ForegroundColor Red
    exit 1
}

# --- Stage, commit, push ---
Write-Host "== Staging files ==" -ForegroundColor Cyan
git add -A
if ($LASTEXITCODE -ne 0) { exit 1 }

if (-not (git diff --cached --quiet)) {
    git commit -m $Message
    if ($LASTEXITCODE -ne 0) { exit 1 }
    Write-Host "== Pushing ==" -ForegroundColor Cyan
    git push
    if ($LASTEXITCODE -ne 0) { exit 1 }
    Write-Host "Done. Pushed to remote." -ForegroundColor Green
} else {
    Write-Host "No changes to commit." -ForegroundColor Yellow
}
