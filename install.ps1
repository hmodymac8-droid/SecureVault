<#
  Builds SecureVault and installs it into Program Files, which only administrators can write to.

  Why it builds this way: building elevated inside a folder your normal account can write to would let
  user-level malware plant a Directory.Build.targets, swap NuGet packages in ~\.nuget, or replace files in
  publish\ before the copy, and so gain admin rights or a trojaned exe. This script instead:
    1. copies only the source files into an admin-only build folder under %ProgramData%,
    2. restores NuGet packages into an admin-only cache in --locked-mode, so the content hashes in
       packages.lock.json must match,
    3. tests and publishes there (self-contained, so DOTNET_ROOT and a user-writable runtime don't matter),
    4. copies the result into Program Files, so libsodium.dll sits next to the exe, never in %TEMP%.
  It still trusts the source files you have checked out: review the diff of anything you pull.

  Run from an elevated PowerShell in the repo folder:
      powershell -ExecutionPolicy Bypass -File .\install.ps1
#>
#Requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'

$repo   = $PSScriptRoot
$target = Join-Path $env:ProgramFiles 'SecureVault'
$build  = Join-Path $env:ProgramData 'SecureVault-build'
$nuget  = Join-Path $build '.nuget'

function Set-AdminOnly($path) {
    # SYSTEM + Administrators full, nobody else. No inheritance from the (user-writable?) parent.
    icacls $path /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" | Out-Null
}

if (Get-Process SecureVault -ErrorAction SilentlyContinue) { throw "Close SecureVault before installing." }

Write-Host "Preparing admin-only build folder $build ..."
if (Test-Path $build) { Remove-Item $build -Recurse -Force }
New-Item -ItemType Directory -Path $build | Out-Null
Set-AdminOnly $build

# Copy sources only: no bin/obj/publish, and no stray build-customisation files.
$items = 'src', 'tests', 'Directory.Build.props', 'SecureVault.slnx'
foreach ($i in $items) { Copy-Item (Join-Path $repo $i) $build -Recurse }
Get-ChildItem $build -Recurse -Directory -Include bin, obj | Remove-Item -Recurse -Force
$unexpected = Get-ChildItem $build -Recurse -File -Include 'Directory.Build.targets', 'Directory.Packages.props', 'nuget.config', '*.rsp'
if ($unexpected) { throw "Unexpected build-customisation files in the source tree: $($unexpected.FullName -join ', ')" }

$env:NUGET_PACKAGES = $nuget            # admin-only package cache
$env:DOTNET_CLI_TELEMETRY_OPTOUT = '1'
$env:DOTNET_NOLOGO = '1'
Push-Location $build
try {
    Write-Host "Restoring packages (locked mode: hashes must match packages.lock.json)..."
    dotnet restore SecureVault.slnx --locked-mode
    if ($LASTEXITCODE -ne 0) { throw "Restore failed or package hashes didn't match the lock files." }

    Write-Host "Running tests..."
    dotnet test SecureVault.slnx -c Release --no-restore
    if ($LASTEXITCODE -ne 0) { throw "Tests failed; not installing." }

    Write-Host "Publishing (self-contained win-x64, no single-file extraction)..."
    $out = Join-Path $build 'publish'
    dotnet publish src\Vault.App\Vault.App.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=false -o $out
    if ($LASTEXITCODE -ne 0) { throw "Publish failed." }
    if (-not (Test-Path (Join-Path $out 'libsodium.dll'))) { throw "libsodium.dll missing from publish output." }

    Write-Host "Installing to $target ..."
    if (Test-Path $target) { Remove-Item $target -Recurse -Force }
    New-Item -ItemType Directory -Path $target | Out-Null
    Copy-Item (Join-Path $out '*') $target -Recurse
    # Admins/SYSTEM full; users and app containers read+execute only.
    icacls $target /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-32-545:(OI)(CI)RX" "*S-1-15-2-1:(OI)(CI)RX" | Out-Null
}
finally { Pop-Location }

Write-Host "Self-test of the installed copy..."
$report = Join-Path $build 'selftest.txt'
$p = Start-Process (Join-Path $target 'SecureVault.exe') -ArgumentList '--selftest', "`"$report`"" -Wait -PassThru
Get-Content $report
if ($p.ExitCode -ne 0) { Write-Warning "Self-test reported a problem (see above)." }

$lnk = Join-Path ([Environment]::GetFolderPath('CommonStartMenu')) 'Programs\SecureVault.lnk'
$ws = New-Object -ComObject WScript.Shell
$s = $ws.CreateShortcut($lnk); $s.TargetPath = Join-Path $target 'SecureVault.exe'; $s.WorkingDirectory = $target; $s.Save()

Remove-Item $build -Recurse -Force
Write-Host ""
Write-Host "Installed. Start it from the Start menu ('SecureVault')."
Write-Host "Optional: sign $target\SecureVault.exe with your code-signing certificate."
