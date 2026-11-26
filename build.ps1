<#
.SYNOPSIS
  Builds, tests and packages SimpleSSH into an MSI.

.EXAMPLE
  ./build.ps1                     # test + publish + MSI (version 1.4.6)
  ./build.ps1 -Version 1.5.0      # bump the MSI/product version (required for upgrades)
  ./build.ps1 -SkipTests

  Output: artifacts\installer\SimpleSSH-<version>-x64.msi
#>
param(
    [string]$Version = "1.4.6",
    [string]$Configuration = "Release",
    [switch]$SkipTests
)

$ErrorActionPreference = "Stop"
$root = $PSScriptRoot
$publishDir = Join-Path $root "artifacts\publish\"
$env:DOTNET_CLI_TELEMETRY_OPTOUT = "1"

function Step($name, [scriptblock]$body) {
    Write-Host "`n==> $name" -ForegroundColor Cyan
    & $body
    if ($LASTEXITCODE -ne 0) { throw "$name failed (exit $LASTEXITCODE)" }
}

if (-not $SkipTests) {
    if (-not (Test-Path (Join-Path $root "tools\testserver\node_modules\ssh2"))) {
        # Run npm from the folder itself: through npm's PowerShell wrapper, --prefix is ignored and npm looks in the current folder.
        Step "npm install (test SSH server)" {
            Push-Location (Join-Path $root "tools\testserver")
            try { npm install --no-audit --no-fund } finally { Pop-Location }
        }
    }
    Step "Run tests" { dotnet test (Join-Path $root "SimpleSSH.sln") -c $Configuration --nologo }
}

if (Test-Path $publishDir) { Remove-Item $publishDir -Recurse -Force }

Step "Publish app (self-contained win-x64)" {
    dotnet publish (Join-Path $root "src\SimpleSSH\SimpleSSH.csproj") -c $Configuration -r win-x64 --self-contained true `
        -p:Version=$Version -p:DebugType=none -o $publishDir --nologo
}

Step "Build MSI" {
    dotnet build (Join-Path $root "installer\SimpleSSH.Installer.wixproj") -c $Configuration --nologo `
        -p:ProductVersion=$Version -p:PublishDir=$publishDir
}

$msi = Join-Path $root "artifacts\installer\SimpleSSH-$Version-x64.msi"
Write-Host "`nDone: $msi ($([math]::Round((Get-Item $msi).Length / 1MB, 1)) MB)" -ForegroundColor Green
