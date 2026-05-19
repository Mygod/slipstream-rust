[CmdletBinding()]
param(
    [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path,
    [string]$PicoquicDir = "",
    [string]$StageDir = "",
    [string]$OpenSslStageDir = "",
    [string]$Configuration = "Release",
    [string]$Platform = "x64"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

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
        },
        @{
            Ssl = "libssl.lib"
            Crypto = "libcrypto.lib"
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
    $vcpkgTriplet = if ($Platform -ieq "ARM64") {
        "arm64-windows-static-md"
    } else {
        "x64-windows-static-md"
    }
    foreach ($path in @($env:VCPKG_INSTALLATION_ROOT, $env:VCPKG_ROOT, "C:\vcpkg")) {
        if (![string]::IsNullOrWhiteSpace($path)) {
            $opensslPaths += Join-Path $path "installed\$vcpkgTriplet"
        }
    }

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

function Export-PicoquicStage {
    param(
        [Parameter(Mandatory = $true)]
        [string]$PicoquicDir,
        [Parameter(Mandatory = $true)]
        [string]$PicotlsIncludeDir,
        [Parameter(Mandatory = $true)]
        [string]$StageDir
    )

    Export-EnvValue -Name "PICOQUIC_INCLUDE_DIR" -Value (Join-Path $PicoquicDir "picoquic")
    Export-EnvValue -Name "PICOQUIC_LIB_DIR" -Value $StageDir
    Export-EnvValue -Name "PICOTLS_INCLUDE_DIR" -Value $PicotlsIncludeDir
}

function Get-CMakeLibraryPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$BuildDir,
        [Parameter(Mandatory = $true)]
        [string[]]$Names,
        [Parameter(Mandatory = $true)]
        [string]$Configuration
    )

    foreach ($name in $Names) {
        $foundLibraries = Get-ChildItem -Path $BuildDir -Filter $name -Recurse -File |
            Where-Object { $_.FullName -match "\\$Configuration\\" } |
            Sort-Object FullName
        if ($foundLibraries) {
            return $foundLibraries[0].FullName
        }
    }

    return $null
}

function Get-PkgConfigExecutable {
    $candidates = @()
    foreach ($path in @($env:PKG_CONFIG_EXECUTABLE, $env:PKG_CONFIG)) {
        if (![string]::IsNullOrWhiteSpace($path)) {
            $candidates += $path
        }
    }

    $commands = @(Get-Command pkg-config.exe, pkgconf.exe -ErrorAction SilentlyContinue)
    foreach ($command in $commands) {
        if ($command) {
            $candidates += $command.Source
        }
    }

    foreach ($candidate in $candidates) {
        if (Test-Path $candidate) {
            return (Resolve-Path $candidate).Path
        }
    }

    return $null
}

function Copy-CMakeLibrary {
    param(
        [Parameter(Mandatory = $true)]
        [string]$BuildDir,
        [Parameter(Mandatory = $true)]
        [string]$StageDir,
        [Parameter(Mandatory = $true)]
        [string[]]$Names,
        [Parameter(Mandatory = $true)]
        [string]$Configuration,
        [switch]$Required
    )

    $libPath = Get-CMakeLibraryPath -BuildDir $BuildDir -Names $Names -Configuration $Configuration
    if (!$libPath) {
        if ($Required) {
            throw "Missing expected CMake library. Checked names: $($Names -join ', ')"
        }
        return
    }
    Copy-Item -Force $libPath $StageDir
}

function Invoke-CMakePicoquicBuild {
    param(
        [Parameter(Mandatory = $true)]
        [string]$PicoquicDir,
        [Parameter(Mandatory = $true)]
        [string]$BuildDir,
        [Parameter(Mandatory = $true)]
        [string]$StageDir,
        [Parameter(Mandatory = $true)]
        [string]$OpenSslStageDir,
        [Parameter(Mandatory = $true)]
        [string]$Configuration,
        [Parameter(Mandatory = $true)]
        [string]$Platform
    )

    $picotlsWindowsCompatOverlay = Join-Path $RepoRoot "scripts\cmake\picotls-windows-compat.cmake"
    if (!(Test-Path $picotlsWindowsCompatOverlay)) {
        throw "picotls Windows compatibility CMake overlay not found at $picotlsWindowsCompatOverlay"
    }
    $picotlsWindowsCompatOverlay = $picotlsWindowsCompatOverlay.Replace('\', '/')
    $cmakeArgs = @(
        "-S", $PicoquicDir,
        "-B", $BuildDir,
        "-G", "Visual Studio 17 2022",
        "-A", $Platform,
        "-DPICOQUIC_FETCH_PTLS=ON",
        "-DBUILD_DEMO=OFF",
        "-DBUILD_HTTP=OFF",
        "-DBUILD_LOGLIB=OFF",
        "-DBUILD_LOGREADER=OFF",
        "-Dpicoquic_BUILD_TESTS=OFF",
        "-DOPENSSL_ROOT_DIR=$OpenSslStageDir",
        "-DOPENSSL_USE_STATIC_LIBS=ON",
        "-DCMAKE_PROJECT_picotls_INCLUDE=$picotlsWindowsCompatOverlay",
        "-DCMAKE_POLICY_VERSION_MINIMUM=3.5"
    )
    $pkgConfigExecutable = Get-PkgConfigExecutable
    if ($pkgConfigExecutable) {
        $cmakeArgs += "-DPKG_CONFIG_EXECUTABLE=$pkgConfigExecutable"
    }
    & cmake @cmakeArgs
    if ($LASTEXITCODE -ne 0) {
        throw "CMake configure failed for picoquic"
    }
    & cmake --build $BuildDir --config $Configuration --target picoquic-core
    if ($LASTEXITCODE -ne 0) {
        throw "CMake build failed for picoquic"
    }

    $picotlsIncludeDir = Join-Path $BuildDir "_deps\picotls-src\include"
    if (!(Test-Path $picotlsIncludeDir)) {
        throw "CMake picotls include directory not found at $picotlsIncludeDir"
    }

    New-Item -ItemType Directory -Force -Path $StageDir | Out-Null
    Copy-CMakeLibrary -BuildDir $BuildDir -StageDir $StageDir -Names @("picoquic-core.lib", "picoquic.lib") -Configuration $Configuration -Required
    Copy-CMakeLibrary -BuildDir $BuildDir -StageDir $StageDir -Names @("picotls-core.lib") -Configuration $Configuration -Required
    Copy-CMakeLibrary -BuildDir $BuildDir -StageDir $StageDir -Names @("picotls-openssl.lib") -Configuration $Configuration -Required
    Copy-CMakeLibrary -BuildDir $BuildDir -StageDir $StageDir -Names @("picotls-minicrypto.lib") -Configuration $Configuration -Required
    Copy-CMakeLibrary -BuildDir $BuildDir -StageDir $StageDir -Names @("picotls-fusion.lib") -Configuration $Configuration
    Copy-CMakeLibrary -BuildDir $BuildDir -StageDir $StageDir -Names @("picotls-minicrypto-deps.lib") -Configuration $Configuration
    Copy-CMakeLibrary -BuildDir $BuildDir -StageDir $StageDir -Names @("cifra.lib") -Configuration $Configuration
    Copy-CMakeLibrary -BuildDir $BuildDir -StageDir $StageDir -Names @("microecc.lib") -Configuration $Configuration
    New-Item -ItemType File -Force -Path (Join-Path $StageDir "picotls-minicrypto-deps-embedded.marker") | Out-Null
    Export-PicoquicStage -PicoquicDir $PicoquicDir -PicotlsIncludeDir $picotlsIncludeDir -StageDir $StageDir
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

$opensslLayout = Get-OpenSslLayout
Initialize-OpenSslStage -Layout $opensslLayout -StageDir $OpenSslStageDir

$cmakeBuildDir = Join-Path (Split-Path -Parent $StageDir) "cmake"
Invoke-CMakePicoquicBuild `
    -PicoquicDir $PicoquicDir `
    -BuildDir $cmakeBuildDir `
    -StageDir $StageDir `
    -OpenSslStageDir $OpenSslStageDir `
    -Configuration $Configuration `
    -Platform $Platform

Get-ChildItem -Path $StageDir -Filter "*.lib" |
    Sort-Object Name |
    Select-Object Name, FullName |
    Format-Table -AutoSize |
    Out-String |
    Write-Host

Write-Host "Staged Windows picoquic artifacts in $StageDir"
Write-Host "picoquic headers: $(Join-Path $PicoquicDir 'picoquic')"
Write-Host "picotls headers: $env:PICOTLS_INCLUDE_DIR"
