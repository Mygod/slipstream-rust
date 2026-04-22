[CmdletBinding()]
param(
    [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path,
    [string]$PicoquicDir = "",
    [string]$PicotlsDir = "",
    [string]$StageDir = "",
    [string]$PicotlsCommit = "5a4461d8a3948d9d26bf861e7d90cb80d8093515",
    [string]$Configuration = "Release",
    [string]$Platform = "x64",
    [string]$PlatformToolset = "v143",
    [string]$WindowsSdk = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Invoke-Git {
    param(
        [Parameter(Mandatory = $true)]
        [string]$WorkingDir,
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments
    )

    & git -C $WorkingDir @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "git failed in $WorkingDir: git $($Arguments -join ' ')"
    }
}

function Invoke-MSBuildProject {
    param(
        [Parameter(Mandatory = $true)]
        [string]$MsBuild,
        [Parameter(Mandatory = $true)]
        [string]$Project,
        [string]$Target = "",
        [Parameter(Mandatory = $true)]
        [string]$Configuration,
        [Parameter(Mandatory = $true)]
        [string]$Platform,
        [Parameter(Mandatory = $true)]
        [string]$PlatformToolset,
        [Parameter(Mandatory = $true)]
        [string]$WindowsSdk
    )

    $args = @(
        "/p:Configuration=$Configuration",
        "/p:Platform=$Platform",
        "/p:PlatformToolset=$PlatformToolset",
        "/p:WindowsTargetPlatformVersion=$WindowsSdk",
        "/m"
    )
    if (![string]::IsNullOrWhiteSpace($Target)) {
        $args += "/t:$Target"
    }
    $args += $Project
    & $MsBuild @args
    if ($LASTEXITCODE -ne 0) {
        throw "MSBuild failed for $Project"
    }
}

function Get-FirstExistingPath {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Candidates
    )

    foreach ($candidate in $Candidates) {
        if (Test-Path $candidate) {
            return $candidate
        }
    }

    return $null
}

function Get-MSBuildPath {
    $vswhere = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\vswhere.exe"
    if (!(Test-Path $vswhere)) {
        throw "Could not locate vswhere.exe"
    }

    $msbuild = & $vswhere -latest -requires Microsoft.Component.MSBuild -find MSBuild\**\Bin\MSBuild.exe |
        Select-Object -First 1
    if (!$msbuild) {
        throw "Could not locate MSBuild.exe"
    }

    return $msbuild
}

function Get-WindowsSdkVersion {
    $sdkRoot = Join-Path ${env:ProgramFiles(x86)} "Windows Kits\10\Include"
    $windowsSdk = Get-ChildItem $sdkRoot -Directory |
        Where-Object { $_.Name -match '^\d+\.\d+\.\d+\.\d+$' } |
        Sort-Object { [version]$_.Name } -Descending |
        Select-Object -First 1 -ExpandProperty Name
    if (!$windowsSdk) {
        throw "Could not locate an installed Windows SDK"
    }

    return $windowsSdk
}

if (!$IsWindows) {
    throw "scripts/build_picoquic_windows.ps1 must be run on a Windows host."
}

if ([string]::IsNullOrWhiteSpace($PicoquicDir)) {
    if ($env:PICOQUIC_DIR) {
        $PicoquicDir = $env:PICOQUIC_DIR
    } else {
        $PicoquicDir = Join-Path $RepoRoot "vendor\picoquic"
    }
}

if ([string]::IsNullOrWhiteSpace($PicotlsDir)) {
    $PicotlsDir = Join-Path $RepoRoot "vendor\picotls"
}

if ([string]::IsNullOrWhiteSpace($StageDir)) {
    $stageRoot = if ($env:PICOQUIC_BUILD_DIR) {
        $env:PICOQUIC_BUILD_DIR
    } else {
        Join-Path $RepoRoot ".picoquic-build\windows"
    }
    $StageDir = Join-Path $stageRoot "$Platform\$Configuration"
}

if (!(Test-Path $PicoquicDir)) {
    throw "picoquic not found at $PicoquicDir. Run: git submodule update --init --recursive vendor/picoquic"
}

if ([string]::IsNullOrWhiteSpace($env:OPENSSL_LIB_DIR)) {
    throw "OPENSSL_LIB_DIR must be set for the Windows picoquic build."
}
if ([string]::IsNullOrWhiteSpace($env:OPENSSL64DIR)) {
    throw "OPENSSL64DIR must be set for the Windows picoquic build."
}
if (!(Test-Path $env:OPENSSL64DIR)) {
    throw "OPENSSL64DIR does not exist: $env:OPENSSL64DIR"
}

$msbuild = Get-MSBuildPath
if ([string]::IsNullOrWhiteSpace($WindowsSdk)) {
    $WindowsSdk = Get-WindowsSdkVersion
}

if (!(Test-Path $PicotlsDir)) {
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $PicotlsDir) | Out-Null
    & git clone https://github.com/h2o/picotls $PicotlsDir
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to clone picotls into $PicotlsDir"
    }
}

$libcrypto = Get-ChildItem -Path $env:OPENSSL_LIB_DIR -Filter "libcrypto*.lib" |
    Sort-Object Name |
    Select-Object -First 1
if (!$libcrypto) {
    throw "Could not find libcrypto import library under $env:OPENSSL_LIB_DIR"
}
Copy-Item -Force $libcrypto.FullName (Join-Path $env:OPENSSL64DIR "libcrypto.lib")

Invoke-Git -WorkingDir $PicotlsDir -Arguments @("fetch", "--depth", "1", "origin", $PicotlsCommit)
Invoke-Git -WorkingDir $PicotlsDir -Arguments @("checkout", "-q", $PicotlsCommit)
Invoke-Git -WorkingDir $PicotlsDir -Arguments @("submodule", "update", "--init", "--recursive")

$picotlsProjects = @(
    "picotlsvs\picotls-core\picotls-core.vcxproj",
    "picotlsvs\picotls-openssl\picotls-openssl.vcxproj",
    "picotlsvs\picotls-minicrypto\picotls-minicrypto.vcxproj",
    "picotlsvs\picotls-fusion\picotls-fusion.vcxproj",
    "picotlsvs\cifra\cifra.vcxproj",
    "picotlsvs\microecc\microecc.vcxproj"
)
foreach ($project in $picotlsProjects) {
    Invoke-MSBuildProject `
        -MsBuild $msbuild `
        -Project (Join-Path $PicotlsDir $project) `
        -Configuration $Configuration `
        -Platform $Platform `
        -PlatformToolset $PlatformToolset `
        -WindowsSdk $WindowsSdk
}

Invoke-MSBuildProject `
    -MsBuild $msbuild `
    -Project (Join-Path $PicoquicDir "picoquic.sln") `
    -Target "picoquic" `
    -Configuration $Configuration `
    -Platform $Platform `
    -PlatformToolset $PlatformToolset `
    -WindowsSdk $WindowsSdk

New-Item -ItemType Directory -Force -Path $StageDir | Out-Null
$requiredLibs = @(
    @{
        Name = "picoquic.lib"
        Candidates = @(
            (Join-Path $PicoquicDir "$Platform\$Configuration\picoquic.lib"),
            (Join-Path $PicoquicDir "picoquic\$Platform\$Configuration\picoquic.lib")
        )
    },
    @{
        Name = "picotls-core.lib"
        Candidates = @(
            (Join-Path $PicotlsDir "picotlsvs\picotls-core\$Platform\$Configuration\picotls-core.lib"),
            (Join-Path $PicotlsDir "picotlsvs\$Platform\$Configuration\picotls-core.lib")
        )
    },
    @{
        Name = "picotls-openssl.lib"
        Candidates = @(
            (Join-Path $PicotlsDir "picotlsvs\picotls-openssl\$Platform\$Configuration\picotls-openssl.lib"),
            (Join-Path $PicotlsDir "picotlsvs\$Platform\$Configuration\picotls-openssl.lib")
        )
    },
    @{
        Name = "picotls-minicrypto.lib"
        Candidates = @(
            (Join-Path $PicotlsDir "picotlsvs\picotls-minicrypto\$Platform\$Configuration\picotls-minicrypto.lib"),
            (Join-Path $PicotlsDir "picotlsvs\$Platform\$Configuration\picotls-minicrypto.lib")
        )
    },
    @{
        Name = "picotls-fusion.lib"
        Candidates = @(
            (Join-Path $PicotlsDir "picotlsvs\picotls-fusion\$Platform\$Configuration\picotls-fusion.lib"),
            (Join-Path $PicotlsDir "picotlsvs\$Platform\$Configuration\picotls-fusion.lib")
        )
    },
    @{
        Name = "cifra.lib"
        Candidates = @(
            (Join-Path $PicotlsDir "picotlsvs\cifra\$Platform\$Configuration\cifra.lib"),
            (Join-Path $PicotlsDir "picotlsvs\$Platform\$Configuration\cifra.lib")
        )
    },
    @{
        Name = "microecc.lib"
        Candidates = @(
            (Join-Path $PicotlsDir "picotlsvs\microecc\$Platform\$Configuration\microecc.lib"),
            (Join-Path $PicotlsDir "picotlsvs\$Platform\$Configuration\microecc.lib")
        )
    }
)

foreach ($lib in $requiredLibs) {
    $libPath = Get-FirstExistingPath -Candidates $lib.Candidates
    if (!$libPath) {
        throw "Missing expected Windows library $($lib.Name). Checked: $($lib.Candidates -join ', ')"
    }
    Copy-Item -Force $libPath $StageDir
}

Get-ChildItem -Path $StageDir -Filter "*.lib" |
    Sort-Object Name |
    Select-Object Name, FullName |
    Format-Table -AutoSize |
    Out-String |
    Write-Host

Write-Host "Staged Windows picoquic artifacts in $StageDir"
Write-Host "picoquic headers: $(Join-Path $PicoquicDir 'picoquic')"
Write-Host "picotls headers: $(Join-Path $PicotlsDir 'include')"
