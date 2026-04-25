[CmdletBinding()]
param(
    [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path,
    [string]$PicoquicDir = "",
    [string]$PicotlsDir = "",
    [string]$StageDir = "",
    [string]$OpenSslStageDir = "",
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
        throw "git failed in ${WorkingDir}: git $($Arguments -join ' ')"
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

function Get-OpenSslStaticLibraryPair {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$LibDirs
    )

    $pairs = @(
        @{
            Ssl = "libssl64MD.lib"
            Crypto = "libcrypto64MD.lib"
        },
        @{
            Ssl = "libssl_static.lib"
            Crypto = "libcrypto_static.lib"
        }
    )

    foreach ($libDir in $LibDirs) {
        if (!(Test-Path $libDir)) {
            continue
        }

        foreach ($pair in $pairs) {
            $ssl = Join-Path $libDir $pair["Ssl"]
            $crypto = Join-Path $libDir $pair["Crypto"]
            if ((Test-Path $ssl) -and (Test-Path $crypto)) {
                return @{
                    LibDir = $libDir
                    Ssl = $ssl
                    Crypto = $crypto
                    SslName = [System.IO.Path]::GetFileNameWithoutExtension($ssl)
                    CryptoName = [System.IO.Path]::GetFileNameWithoutExtension($crypto)
                }
            }
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

function Export-EnvValue {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [Parameter(Mandatory = $true)]
        [string]$Value
    )

    Set-Item -Path "Env:$Name" -Value $Value
    if ($env:GITHUB_ENV) {
        "$Name=$Value" | Out-File -FilePath $env:GITHUB_ENV -Append -Encoding utf8
    }
}

function Get-OpenSslLayout {
    if (![string]::IsNullOrWhiteSpace($env:OPENSSL_LIB_DIR) -and
        ![string]::IsNullOrWhiteSpace($env:OPENSSL_INCLUDE_DIR)) {
        if (!(Test-Path $env:OPENSSL_LIB_DIR)) {
            throw "OPENSSL_LIB_DIR does not exist: $env:OPENSSL_LIB_DIR"
        }
        if (!(Test-Path $env:OPENSSL_INCLUDE_DIR)) {
            throw "OPENSSL_INCLUDE_DIR does not exist: $env:OPENSSL_INCLUDE_DIR"
        }
        $staticPair = Get-OpenSslStaticLibraryPair -LibDirs @(
            $env:OPENSSL_LIB_DIR,
            (Join-Path $env:OPENSSL_LIB_DIR "VC"),
            (Join-Path $env:OPENSSL_LIB_DIR "VC\x64\MD")
        )
        if (!$staticPair) {
            throw "Could not find static OpenSSL libraries under OPENSSL_LIB_DIR: $env:OPENSSL_LIB_DIR"
        }
        return @{
            Root = if ($env:OPENSSL_ROOT_DIR) { $env:OPENSSL_ROOT_DIR } else { Split-Path -Parent $env:OPENSSL_INCLUDE_DIR }
            IncludeDir = $env:OPENSSL_INCLUDE_DIR
            LibDir = $staticPair["LibDir"]
            Ssl = $staticPair["Ssl"]
            Crypto = $staticPair["Crypto"]
            SslName = $staticPair["SslName"]
            CryptoName = $staticPair["CryptoName"]
        }
    }

    $opensslPaths = @()
    foreach ($path in @($env:OPENSSL_ROOT_DIR, $env:OPENSSL_DIR, $env:OPENSSL64DIR)) {
        if (![string]::IsNullOrWhiteSpace($path)) {
            $opensslPaths += $path
        }
    }
    $opensslPaths += @(
        "C:\Program Files\OpenSSL",
        "C:\Program Files\OpenSSL-Win64",
        "C:\OpenSSL-Win64",
        "C:\OpenSSL"
    )

    foreach ($path in $opensslPaths) {
        if (!(Test-Path $path)) {
            continue
        }
        $includeDir = Join-Path $path "include"
        if (!(Test-Path $includeDir)) {
            continue
        }
        $libRoot = Join-Path $path "lib"
        $staticPair = Get-OpenSslStaticLibraryPair -LibDirs @(
            (Join-Path $libRoot "VC"),
            (Join-Path $libRoot "VC\x64\MD"),
            $libRoot
        )
        if ($staticPair) {
            return @{
                Root = $path
                IncludeDir = $includeDir
                LibDir = $staticPair["LibDir"]
                Ssl = $staticPair["Ssl"]
                Crypto = $staticPair["Crypto"]
                SslName = $staticPair["SslName"]
                CryptoName = $staticPair["CryptoName"]
            }
        }
    }

    throw "Could not locate an OpenSSL install with include files and static MSVC libraries."
}

function Initialize-OpenSslStage {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Layout,
        [Parameter(Mandatory = $true)]
        [string]$StageDir
    )

    $sourceIncludeDir = $Layout["IncludeDir"]
    $sourceSsl = $Layout["Ssl"]
    $sourceCrypto = $Layout["Crypto"]
    $sslName = $Layout["SslName"]
    $cryptoName = $Layout["CryptoName"]
    $stageIncludeDir = Join-Path $StageDir "include"
    $stageLibDir = Join-Path $StageDir "lib"

    New-Item -ItemType Directory -Force -Path $stageIncludeDir, $stageLibDir | Out-Null
    Copy-Item -Recurse -Force (Join-Path $sourceIncludeDir "*") $stageIncludeDir

    Copy-Item -Force $sourceCrypto $stageLibDir
    Copy-Item -Force $sourceSsl $stageLibDir

    Export-EnvValue -Name "OPENSSL_DIR" -Value $StageDir
    Export-EnvValue -Name "OPENSSL_ROOT_DIR" -Value $StageDir
    Export-EnvValue -Name "OPENSSL64DIR" -Value $StageDir
    Export-EnvValue -Name "OPENSSL_INCLUDE_DIR" -Value $stageIncludeDir
    Export-EnvValue -Name "OPENSSL_LIB_DIR" -Value $stageLibDir
    Export-EnvValue -Name "OPENSSL_SSL_LIBRARY" -Value (Join-Path $stageLibDir (Split-Path -Leaf $sourceSsl))
    Export-EnvValue -Name "OPENSSL_CRYPTO_LIBRARY" -Value (Join-Path $stageLibDir (Split-Path -Leaf $sourceCrypto))
    Export-EnvValue -Name "OPENSSL_LIBS" -Value "${sslName}:${cryptoName}"
    Export-EnvValue -Name "OPENSSL_STATIC" -Value "1"
    Export-EnvValue -Name "OPENSSL_USE_STATIC_LIBS" -Value "TRUE"
    $sourceRoot = $Layout["Root"]
    Write-Host "Static OpenSSL staged in $StageDir from $sourceRoot"
    Write-Host "OpenSSL libraries: ${sslName}, ${cryptoName}"
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

if ([string]::IsNullOrWhiteSpace($OpenSslStageDir)) {
    $stagePlatformDir = Split-Path -Parent $StageDir
    $stageRootDir = Split-Path -Parent $stagePlatformDir
    $OpenSslStageDir = Join-Path $stageRootDir "openssl"
}

if (!(Test-Path $PicoquicDir)) {
    throw "picoquic not found at $PicoquicDir. Run: git submodule update --init --recursive vendor/picoquic"
}

$msbuild = Get-MSBuildPath
if ([string]::IsNullOrWhiteSpace($WindowsSdk)) {
    $WindowsSdk = Get-WindowsSdkVersion
}

$opensslLayout = Get-OpenSslLayout
Initialize-OpenSslStage -Layout $opensslLayout -StageDir $OpenSslStageDir

if (!(Test-Path $PicotlsDir)) {
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $PicotlsDir) | Out-Null
    & git clone https://github.com/h2o/picotls $PicotlsDir
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to clone picotls into $PicotlsDir"
    }
}

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
