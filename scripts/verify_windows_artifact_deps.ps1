[CmdletBinding()]
param(
    [string]$DistDir = "dist",
    [string]$TargetPlatform = "x64"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Get-DumpbinPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$TargetPlatform
    )

    $vswhere = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\vswhere.exe"
    if (!(Test-Path $vswhere)) {
        throw "Could not locate vswhere.exe"
    }

    $vcToolsRequirement = if ($TargetPlatform -ieq "ARM64") {
        "Microsoft.VisualStudio.Component.VC.Tools.ARM64"
    } else {
        "Microsoft.VisualStudio.Component.VC.Tools.x86.x64"
    }
    $installPath = & $vswhere -latest -requires $vcToolsRequirement -property installationPath
    if (!$installPath) {
        $installPath = & $vswhere -latest -requires Microsoft.Component.MSBuild -property installationPath
    }
    if (!$installPath) {
        throw "Could not locate a Visual Studio installation with VC tools"
    }

    $msvcRoot = Join-Path $installPath "VC\Tools\MSVC"
    $targetDir = if ($TargetPlatform -ieq "ARM64") {
        "arm64"
    } else {
        "x64"
    }
    $dumpbin = Get-ChildItem -Path $msvcRoot -Filter "dumpbin.exe" -Recurse |
        Where-Object {
            $_.FullName -like "*\bin\Hostarm64\$targetDir\dumpbin.exe" -or
            $_.FullName -like "*\bin\HostARM64\$targetDir\dumpbin.exe" -or
            $_.FullName -like "*\bin\Hostx64\$targetDir\dumpbin.exe" -or
            $_.FullName -like "*\bin\HostX64\$targetDir\dumpbin.exe" -or
            $_.FullName -like "*\bin\Hostx86\$targetDir\dumpbin.exe" -or
            $_.FullName -like "*\bin\HostX86\$targetDir\dumpbin.exe"
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

$dumpbin = Get-DumpbinPath -TargetPlatform $TargetPlatform
$allowedDependencyPatterns = @(
    '^(?i:advapi32|bcrypt|bcryptprimitives|crypt32|gdi32|kernel32|ntdll|user32|vcruntime140|vcruntime140_1|ws2_32)\.dll$',
    '^(?i:ucrtbase)\.dll$',
    '^(?i:api-ms-win-(core|crt)-[a-z0-9-]+)\.dll$'
)
$failed = $false
foreach ($exe in $executables) {
    Write-Host "Checking dependencies for $($exe.FullName)"
    $deps = & $dumpbin /dependents $exe.FullName
    $deps | Out-String | Write-Host
    $dlls = $deps |
        ForEach-Object {
            if ($_ -match '^\s*([A-Za-z0-9_.-]+\.dll)\s*$') {
                $Matches[1]
            }
        } |
        Sort-Object -Unique
    $unexpectedDlls = @()
    foreach ($dll in $dlls) {
        $isAllowed = $false
        foreach ($pattern in $allowedDependencyPatterns) {
            if ($dll -match $pattern) {
                $isAllowed = $true
                break
            }
        }
        if (!$isAllowed) {
            $unexpectedDlls += $dll
        }
    }
    if ($unexpectedDlls) {
        $failed = $true
        Write-Host "Unexpected non-platform DLL dependencies: $($unexpectedDlls -join ', ')"
    }
}

if ($failed) {
    throw "Windows artifacts depend on non-platform DLLs; expected standalone artifacts with only Windows and VC runtime dependencies."
}
