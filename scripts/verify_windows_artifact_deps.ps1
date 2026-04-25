[CmdletBinding()]
param(
    [string]$DistDir = "dist"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Get-DumpbinPath {
    $vswhere = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\vswhere.exe"
    if (!(Test-Path $vswhere)) {
        throw "Could not locate vswhere.exe"
    }

    $installPath = & $vswhere -latest -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    if (!$installPath) {
        throw "Could not locate a Visual Studio installation with VC tools"
    }

    $msvcRoot = Join-Path $installPath "VC\Tools\MSVC"
    $dumpbin = Get-ChildItem -Path $msvcRoot -Filter "dumpbin.exe" -Recurse |
        Where-Object {
            $_.FullName -like "*\bin\Hostx64\x64\dumpbin.exe" -or
            $_.FullName -like "*\bin\HostX64\x64\dumpbin.exe" -or
            $_.FullName -like "*\bin\Hostx86\x64\dumpbin.exe" -or
            $_.FullName -like "*\bin\HostX86\x64\dumpbin.exe"
        } |
        Sort-Object FullName -Descending |
        Select-Object -First 1
    if (!$dumpbin) {
        throw "Could not locate dumpbin.exe under $msvcRoot"
    }

    return $dumpbin.FullName
}

if (!(Test-Path $DistDir)) {
    throw "Distribution directory does not exist: $DistDir"
}

$executables = Get-ChildItem -Path $DistDir -Filter "*.exe"
if (!$executables) {
    throw "No Windows executables found under $DistDir"
}

$dumpbin = Get-DumpbinPath
$failed = $false
foreach ($exe in $executables) {
    Write-Host "Checking dependencies for $($exe.FullName)"
    $deps = & $dumpbin /dependents $exe.FullName
    $deps | Out-String | Write-Host
    if ($deps -match '(?i)\blib(ssl|crypto)(-[^\s]+)?\.dll\b') {
        $failed = $true
    }
}

if ($failed) {
    throw "Windows artifacts depend on OpenSSL DLLs; expected static OpenSSL linkage."
}
