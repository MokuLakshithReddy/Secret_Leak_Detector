# setup-fixture-repo.ps1
# ---------------------
# End-to-end block-and-remediate demonstration for Secret Leak Detector.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File demo/setup-fixture-repo.ps1

$ErrorActionPreference = "Stop"

# Locate the SLD CLI
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot  = Split-Path -Parent $ScriptDir
$CLI       = Join-Path $RepoRoot "dist\cli.js"

if (-not (Test-Path $CLI)) {
  Write-Error "ERROR: $CLI not found. Run 'npm run build' first."
  exit 1
}

# Synthesize test credentials at runtime so this source file is clean
$DemoAwsKey = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QUtJQTJHN1Q0WDlLMU04UDVRM1I="))
$DemoDbUrl  = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("cG9zdGdyZXM6Ly9hZG1pbjpzM2NyM3RQYXN3MHJkMTIzIUBkYi5pbnRlcm5hbC5jb3JwOjU0MzIvbXlhcHA="))

# Create isolated temp fixture repo
$TmpBase = [System.IO.Path]::GetTempPath()
$TmpDir  = Join-Path $TmpBase ("sld-demo-" + [System.Guid]::NewGuid().ToString().Substring(0,8))
New-Item -ItemType Directory -Path $TmpDir | Out-Null
Write-Host "Created fixture repo at: $TmpDir"

Push-Location $TmpDir

try {
  & git init -q
  & git config user.email "demo@example.com"
  & git config user.name "SLD Demo"

  # Write fixture files
  New-Item -ItemType Directory -Path "config" | Out-Null
  Set-Content -Path "config\aws.env" -Value @"
AWS_REGION=us-east-1
AWS_ACCESS_KEY_ID=$DemoAwsKey
"@ -Encoding UTF8

  New-Item -ItemType Directory -Path "db" | Out-Null
  Set-Content -Path "db\connect.js" -Value @"
// Database connection helper
const DATABASE_URL = "$DemoDbUrl";
module.exports = { DATABASE_URL };
"@ -Encoding UTF8

  New-Item -ItemType Directory -Path "src" | Out-Null
  Set-Content -Path "src\api.ts" -Value @"
// API configuration
const API_SECRET = "a3f8c2e1b9d4726e0f5a1c8b3d7e9f2a4c6b8d0e";
export { API_SECRET };
"@ -Encoding UTF8

  New-Item -ItemType Directory -Path "crypto" | Out-Null
  Set-Content -Path "crypto\hash.txt" -Value @"
# These are safe, well-known hash formats - not secrets
commit abc123def456789012345678901234567890abcdef
sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxbd5R/mJnQ=
"@ -Encoding UTF8

  Set-Content -Path "README.md" -Value @"
# Fixture Repository
This repository is an intentional demonstration of credential leaks.
All credentials here are synthetic non-functional test values.
"@ -Encoding UTF8

  # Stage all files
  & git add .

  Write-Host ""
  Write-Host ">> Attempting git commit (would be BLOCKED on hook-installed projects)..."
  Write-Host "   (Hook is not installed in this isolated demo repo - CLI runs directly)"
  try { & git commit -m "add config" -q } catch {}

  # Run SLD CLI scan
  Write-Host ""
  Write-Host ">> Running Secret Leak Detector scan..."
  $ScanOutput = & node $CLI scan . 2>&1
  $ScanExit   = $LASTEXITCODE

  $ScanText = $ScanOutput -join "`n"
  Write-Host $ScanText

  Write-Host ""
  if ($ScanExit -ne 0) {
    Write-Host "============================================================"
    Write-Host "BLOCKED: Secret Leak Detector detected credentials!"
    Write-Host "============================================================"
  }

  # Remediate: replace fake keys with env references
  Write-Host ""
  Write-Host ">> Remediating config/aws.env, db/connect.js, src/api.ts..."

  Set-Content -Path "config\aws.env" -Value @"
AWS_REGION=us-east-1
# Credential removed - load from environment variable at runtime
AWS_ACCESS_KEY_ID=`${AWS_ACCESS_KEY_ID}
"@ -Encoding UTF8

  Set-Content -Path "db\connect.js" -Value @"
// Database connection helper - credential loaded from environment
const DATABASE_URL = process.env.DATABASE_URL;
if (!DATABASE_URL) throw new Error("DATABASE_URL environment variable is not set");
module.exports = { DATABASE_URL };
"@ -Encoding UTF8

  Set-Content -Path "src\api.ts" -Value @"
// API configuration - secret loaded from environment
const API_SECRET = process.env.API_SECRET;
if (!API_SECRET) throw new Error("API_SECRET environment variable is not set");
export { API_SECRET };
"@ -Encoding UTF8

  Set-Content -Path ".env.example" -Value @"
# Copy to .env and fill in real values - NEVER commit .env
AWS_ACCESS_KEY_ID=YOUR_AWS_ACCESS_KEY_ID_HERE
DATABASE_URL=postgres://user:password@localhost:5432/myapp
API_SECRET=your-api-secret-here
"@ -Encoding UTF8

  Write-Host "   Remediated credentials to environment variables"
  Write-Host "   Created .env.example for developer reference"

  # Rescan after remediation
  Write-Host ""
  Write-Host ">> Rescanning after remediation..."
  $RescanOutput = & node $CLI scan . 2>&1
  $RescanExit   = $LASTEXITCODE

  $RescanText = $RescanOutput -join "`n"
  Write-Host $RescanText

  # Summary
  Write-Host ""
  Write-Host "============================================================"
  if ($RescanExit -eq 0) {
    Write-Host "PASS: Post-remediation scan is CLEAN - no blocking findings"
  } else {
    Write-Host "FAIL: Post-remediation scan still reports findings (exit $RescanExit)"
  }
  Write-Host "Fixture repo: $TmpDir"
  Write-Host "============================================================"

  exit $RescanExit
} finally {
  Pop-Location
  try { Remove-Item -Recurse -Force $TmpDir -ErrorAction SilentlyContinue } catch {}
}
