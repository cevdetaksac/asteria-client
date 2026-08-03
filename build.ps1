# Asteria Client - Build Script
# Version is read automatically from client_constants.py (single source of truth)

param(
    [switch]$Clean = $false,
    [switch]$WebRTC = $false,
    [switch]$Sign = $false,
    [switch]$Release = $false,
    [string]$CertPath = $env:HONEYPOT_SIGN_CERT,
    [string]$CertPassword = $env:HONEYPOT_SIGN_CERT_PASSWORD,
    [string]$TimestampUrl = "http://timestamp.digicert.com"
)

if ($Release -and -not $Sign) {
    Write-Host "ERROR: -Release requires -Sign; unsigned production artifacts are forbidden." -ForegroundColor Red
    exit 1
}
if ($Release -and -not $WebRTC) {
    Write-Host "ERROR: -Release requires -WebRTC for the production feature profile." -ForegroundColor Red
    exit 1
}

# ===================== VERSION AUTO-DETECTION ===================== #
# Read VERSION from client_constants.py — the ONLY place version is defined
$versionLine = Select-String -Path "client_constants.py" -Pattern '^VERSION\s*=\s*"([^"]+)"' | Select-Object -First 1
if (-not $versionLine) {
    Write-Host "ERROR: Could not read VERSION from client_constants.py" -ForegroundColor Red
    exit 1
}
$VERSION = $versionLine.Matches[0].Groups[1].Value
$parts = $VERSION.Split('.')
$VMAJOR = $parts[0]
$VMINOR = $parts[1]
$VBUILD = $parts[2]

Write-Host "===============================================" -ForegroundColor Green
Write-Host "  Asteria Client v$VERSION Builder     " -ForegroundColor Green
Write-Host "  Optimized Build                             " -ForegroundColor Green  
Write-Host "===============================================" -ForegroundColor Green

# ===================== VERSION PROPAGATION ===================== #
# Sync version into all files that embed it (installer.nsi, manifest, config, README)
Write-Host "[0/5] Propagating version v$VERSION to all files..." -ForegroundColor Yellow

# installer.nsi — update !define VERSIONMAJOR/MINOR/BUILD
$nsiContent = Get-Content "installer.nsi" -Raw
$nsiContent = $nsiContent -replace '(!define VERSIONMAJOR )\d+', "`${1}$VMAJOR"
$nsiContent = $nsiContent -replace '(!define VERSIONMINOR )\d+', "`${1}$VMINOR"
$nsiContent = $nsiContent -replace '(!define VERSIONBUILD )\d+', "`${1}$VBUILD"
Set-Content "installer.nsi" -Value $nsiContent -NoNewline

# installer.manifest — update version="X.Y.Z.0"
$manifestContent = Get-Content "installer.manifest" -Raw
$manifestContent = $manifestContent -replace 'version="\d+\.\d+\.\d+\.\d+"', "version=`"$VERSION.0`""
Set-Content "installer.manifest" -Value $manifestContent -NoNewline

# client_config.json — update "version": "X.Y.Z"
$configContent = Get-Content "client_config.json" -Raw
$configContent = $configContent -replace '"version":\s*"[^"]+"', "`"version`": `"$VERSION`""
Set-Content "client_config.json" -Value $configContent -NoNewline

# README.md — update **Current Version: X.Y.Z**
$readmeContent = Get-Content "README.md" -Raw
$readmeContent = $readmeContent -replace '\*\*Current Version: [^*]+\*\*', "**Current Version: $VERSION**"
Set-Content "README.md" -Value $readmeContent -NoNewline

Write-Host "   SUCCESS: Version v$VERSION propagated to all files" -ForegroundColor Green

# Clean previous builds if requested
if ($Clean) {
    Write-Host "Cleaning previous builds..." -ForegroundColor Yellow
    Remove-Item -Path "build", "dist", "__pycache__" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "asteria-client-installer.exe", "cloud-client-installer.exe" -Force -ErrorAction SilentlyContinue
    Write-Host "   Cleanup completed" -ForegroundColor Green
}

# Detect Python: prefer .venv if present
$venvPython = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
if (Test-Path $venvPython) {
    $PYTHON = $venvPython
    Write-Host "   Using venv Python: $PYTHON" -ForegroundColor Cyan
} else {
    $PYTHON = "python"
    Write-Host "   Using system Python" -ForegroundColor Cyan
}

# WebRTC/H.264 is an explicit release profile because aiortc/av add native
# binaries. Never produce a build that advertises WebRTC without the runtime.
if ($WebRTC) {
    Write-Host "   WebRTC/H.264 release profile enabled" -ForegroundColor Cyan
    & $PYTHON -c "import aiortc, av, dxcam"
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: WebRTC runtime is missing." -ForegroundColor Red
        Write-Host "Install it with: $PYTHON -m pip install -r requirements-webrtc.txt" -ForegroundColor Yellow
        exit 1
    }
    $env:HONEYPOT_WEBRTC = "1"
} else {
    Remove-Item Env:HONEYPOT_WEBRTC -ErrorAction SilentlyContinue
    Write-Host "   JPEG/WS release profile (use -WebRTC for H.264)" -ForegroundColor Cyan
}

# Step 1: Build Python executable with performance optimizations
Write-Host "[1/5] Building Python executable..." -ForegroundColor Yellow
try {
    & $PYTHON -m PyInstaller asteria-client.spec --clean
    if ($LASTEXITCODE -eq 0) {
        Write-Host "   SUCCESS: Executable built successfully" -ForegroundColor Green
        # Gate: our application modules must NOT appear as plain .py under onedir.
        $onedirInternal = Join-Path (Get-Location) "dist\asteria-client\_internal"
        if (Test-Path $onedirInternal) {
            $leaked = @(Get-ChildItem -Path $onedirInternal -Recurse -Filter "client_*.py" -File -ErrorAction SilentlyContinue)
            $leaked += @(Get-ChildItem -Path $onedirInternal -Recurse -Filter "client.py" -File -ErrorAction SilentlyContinue)
            if ($leaked.Count -gt 0) {
                Write-Host "   ERROR: Plain Python sources leaked into _internal:" -ForegroundColor Red
                $leaked | Select-Object -First 20 | ForEach-Object { Write-Host ("      " + $_.FullName) -ForegroundColor Red }
                Write-Host "   Remove client_*.py from asteria-client.spec datas= (use hiddenimports/PYZ)." -ForegroundColor Yellow
                exit 1
            }
            Write-Host "   SUCCESS: No client_*.py sources in _internal (PYZ bytecode only)" -ForegroundColor Green
        }
    } else {
        throw "PyInstaller failed"
    }
} catch {
    Write-Host "   ERROR: Failed to build executable: $_" -ForegroundColor Red
    exit 1
}

# Build the separate non-elevated WebView GUI. It is deliberately onefile so
# Program Files does not gain a second exposed runtime tree.
Write-Host "[1b/6] Building separate Asteria GUI..." -ForegroundColor Yellow
$npm = Get-Command npm -ErrorAction SilentlyContinue
if (-not $npm) {
    Write-Host "   ERROR: npm is required to build ui/" -ForegroundColor Red
    exit 1
}
Push-Location "ui"
try {
    & npm run build
    if ($LASTEXITCODE -ne 0) { throw "Vite/TypeScript build failed" }
} finally {
    Pop-Location
}
& $PYTHON -c "import webview"
if ($LASTEXITCODE -ne 0) {
    Write-Host "   ERROR: pywebview missing; install requirements-gui.txt" -ForegroundColor Red
    exit 1
}
& $PYTHON -m PyInstaller asteria-gui.spec --clean
if ($LASTEXITCODE -ne 0 -or -not (Test-Path "dist\asteria-gui.exe")) {
    Write-Host "   ERROR: asteria-gui.exe build failed" -ForegroundColor Red
    exit 1
}
Write-Host "   SUCCESS: dist\asteria-gui.exe (onefile)" -ForegroundColor Green

# Step 2: Copy config files to dist (installer root + onedir folder)
Write-Host "[2/5] Copying configuration files..." -ForegroundColor Yellow
try {
    Copy-Item -Path "client_config.json", "client_lang.json", "LICENSE", "README.md" -Destination "dist" -Force
    $onedir = Join-Path "dist" "asteria-client"
    if (Test-Path $onedir) {
        Copy-Item -Path "client_config.json", "client_lang.json", "LICENSE", "README.md" -Destination $onedir -Force
        Write-Host "   SUCCESS: Config copied to dist/ and dist/asteria-client/" -ForegroundColor Green
    } else {
        Write-Host "   SUCCESS: Configuration files copied to dist/" -ForegroundColor Green
        Write-Host "   WARN: dist/asteria-client/ missing - expected onedir output" -ForegroundColor Yellow
    }
} catch {
    Write-Host "   ERROR: Failed to copy files: $_" -ForegroundColor Red
    exit 1
}

# Step 3: Sign PE payloads BEFORE NSIS so the installer embeds signed binaries.
# Signing after makensis only Authenticodes the outer stub; installed exe stay unsigned.
Write-Host "[3/6] Signing payload executables..." -ForegroundColor Yellow
$installerPath = Join-Path (Get-Location) "asteria-client-installer.exe"
$mainExe = Join-Path (Get-Location) "dist\asteria-client\asteria-client.exe"
$guiExe = Join-Path (Get-Location) "dist\asteria-gui.exe"
$signed = $false

function Invoke-AsteriaSign([string[]]$Targets) {
    if (-not $CertPath -or -not (Test-Path $CertPath)) {
        Write-Host "   ERROR: -Sign requires CertPath / HONEYPOT_SIGN_CERT" -ForegroundColor Red
        exit 1
    }
    $signtool = Get-Command signtool.exe -ErrorAction SilentlyContinue
    if (-not $signtool) {
        Write-Host "   ERROR: signtool.exe not found in PATH" -ForegroundColor Red
        exit 1
    }
    foreach ($target in ($Targets | Where-Object { $_ -and (Test-Path $_) })) {
        $signArgs = @(
            "sign", "/fd", "SHA256", "/td", "SHA256", "/tr", $TimestampUrl,
            "/f", $CertPath
        )
        if ($CertPassword) { $signArgs += @("/p", $CertPassword) }
        $signArgs += $target
        & signtool.exe @signArgs
        if ($LASTEXITCODE -ne 0) {
            Write-Host "   ERROR: failed to sign $target" -ForegroundColor Red
            exit 1
        }
        Write-Host "   SIGNED: $target" -ForegroundColor Green
    }
}

if ($Sign) {
    Invoke-AsteriaSign @($mainExe, $guiExe)
    $signed = $true
} else {
    Write-Host "   SKIP: Authenticode payloads (-Sign not set; unsigned build OK for dev)" -ForegroundColor DarkGray
}

# Step 4: Check for NSIS + WebView2 Evergreen payloads
# Prefer offline Standalone x64 (~150 MB) so target hosts need no internet at install.
# Keep tiny bootstrapper as last-resort fallback only.
Write-Host "[4/6] Checking for NSIS + WebView2 runtime payloads..." -ForegroundColor Yellow
$nsisPath = Get-Command makensis -ErrorAction SilentlyContinue
if (-not $nsisPath) {
    Write-Host "   WARNING: NSIS not found, installing via Scoop..." -ForegroundColor Yellow
    try {
        & scoop install nsis
        Write-Host "   SUCCESS: NSIS installed successfully" -ForegroundColor Green
    } catch {
        Write-Host "   ERROR: Failed to install NSIS. Please install manually." -ForegroundColor Red
        Write-Host "      Run: scoop install nsis" -ForegroundColor White
        exit 1
    }
} else {
    Write-Host "   SUCCESS: NSIS found at $($nsisPath.Source)" -ForegroundColor Green
}

$wv2Dir = Join-Path $PSScriptRoot "vendor"
New-Item -ItemType Directory -Force -Path $wv2Dir | Out-Null

# Evergreen Standalone Installer x64 - offline; no download on the target host.
$wv2Standalone = Join-Path $wv2Dir "MicrosoftEdgeWebView2RuntimeInstallerX64.exe"
$wv2StandaloneUrl = "https://go.microsoft.com/fwlink/?linkid=2124701"
$needStandalone = $true
if (Test-Path -LiteralPath $wv2Standalone) {
    $sz = (Get-Item -LiteralPath $wv2Standalone).Length
    if ($sz -ge 40MB) {
        $needStandalone = $false
    } else {
        Write-Host ("   Standalone payload too small ({0} bytes) - re-downloading..." -f $sz) -ForegroundColor Yellow
        Remove-Item -LiteralPath $wv2Standalone -Force -ErrorAction SilentlyContinue
    }
}
if ($needStandalone) {
    Write-Host "   Downloading WebView2 Evergreen Standalone x64 (offline payload)..." -ForegroundColor Yellow
    try {
        Invoke-WebRequest -Uri $wv2StandaloneUrl -OutFile $wv2Standalone -UseBasicParsing
    } catch {
        Write-Host "   ERROR: Failed to download WebView2 standalone installer: $_" -ForegroundColor Red
        Write-Host "      Manual: save MicrosoftEdgeWebView2RuntimeInstallerX64.exe under vendor\" -ForegroundColor White
        exit 1
    }
}
$wv2StandSize = (Get-Item -LiteralPath $wv2Standalone).Length
if ($wv2StandSize -lt 40MB) {
    Write-Host ("   ERROR: WebView2 standalone looks too small ({0} bytes)" -f $wv2StandSize) -ForegroundColor Red
    exit 1
}
Write-Host ("   SUCCESS: WebView2 standalone ready ({0:N1} MB)" -f ($wv2StandSize / 1MB)) -ForegroundColor Green

# Tiny bootstrapper - optional network fallback if standalone somehow missing at runtime.
$wv2Boot = Join-Path $wv2Dir "MicrosoftEdgeWebview2Setup.exe"
if (-not (Test-Path -LiteralPath $wv2Boot) -or ((Get-Item -LiteralPath $wv2Boot).Length -lt 500000)) {
    Write-Host "   Downloading WebView2 Evergreen bootstrapper (fallback)..." -ForegroundColor Yellow
    try {
        Invoke-WebRequest -Uri "https://go.microsoft.com/fwlink/p/?LinkId=2124703" -OutFile $wv2Boot -UseBasicParsing
    } catch {
        Write-Host "   WARNING: bootstrapper download failed (standalone is enough): $_" -ForegroundColor Yellow
    }
}
if (Test-Path -LiteralPath $wv2Boot) {
    $wv2BootSize = (Get-Item -LiteralPath $wv2Boot).Length
    Write-Host ("   SUCCESS: WebView2 bootstrapper ready ({0:N1} KB)" -f ($wv2BootSize / 1KB)) -ForegroundColor Green
}

# Step 5: Build installer (embeds already-signed motor/GUI when -Sign was set)
Write-Host "[5/6] Building installer..." -ForegroundColor Yellow
try {
    & makensis installer.nsi
    if ($LASTEXITCODE -eq 0) {
        Write-Host "   SUCCESS: Installer built successfully" -ForegroundColor Green
    } else {
        throw "NSIS compilation failed"
    }
} catch {
    Write-Host "   ERROR: Failed to build installer: $_" -ForegroundColor Red
    exit 1
}

if ($Sign) {
    Write-Host "[5b/6] Signing outer installer stub..." -ForegroundColor Yellow
    Invoke-AsteriaSign @($installerPath)
}

# Step 6: Show results + emit provenance manifest
Write-Host "`n[6/6] Build completed successfully!" -ForegroundColor Green
Write-Host "===============================================" -ForegroundColor Green

$installerFile = Get-Item "asteria-client-installer.exe" -ErrorAction SilentlyContinue
if ($installerFile) {
    $sizeMB = [math]::Round($installerFile.Length / 1MB, 1)
    $sha = (Get-FileHash -Algorithm SHA256 -Path $installerFile.FullName).Hash.ToLowerInvariant()
    $provenance = [ordered]@{
        product = "asteria-client"
        version = $VERSION
        artifact = "asteria-client-installer.exe"
        sha256 = $sha
        size_bytes = $installerFile.Length
        built_at = (Get-Date).ToUniversalTime().ToString("o")
        webrtc = [bool]$WebRTC
        separate_gui = [bool](Test-Path $guiExe)
        gui_sha256 = if (Test-Path $guiExe) {
            (Get-FileHash -Algorithm SHA256 -Path $guiExe).Hash.ToLowerInvariant()
        } else { $null }
        authenticode_signed = [bool]$signed
        toolchain = @{
            python = (python --version 2>&1 | Out-String).Trim()
            pyinstaller = "asteria-client.spec"
            nsis = "installer.nsi"
        }
    }
    $provPath = "dist\release-provenance-v$VERSION.json"
    New-Item -ItemType Directory -Force -Path "dist" | Out-Null
    $provenance | ConvertTo-Json -Depth 5 | Set-Content -Path $provPath -Encoding UTF8
    Write-Host ("Version:   v{0}" -f $VERSION) -ForegroundColor Cyan
    Write-Host ("Installer: asteria-client-installer.exe ({0} MB)" -f $sizeMB) -ForegroundColor Cyan
    Write-Host ("SHA256:    {0}" -f $sha) -ForegroundColor Cyan
    Write-Host ("Signed:    {0}" -f $signed) -ForegroundColor Cyan
    Write-Host ("Provenance:{0}" -f $provPath) -ForegroundColor Cyan
    Write-Host ("Built:     {0}" -f $installerFile.LastWriteTime) -ForegroundColor Cyan
    Write-Host "Ready for distribution!" -ForegroundColor Green
} else {
    Write-Host "ERROR: Installer file not found!" -ForegroundColor Red
    exit 1
}

Write-Host "`nUsage Instructions:" -ForegroundColor White
Write-Host "   - Run asteria-client-installer.exe as Administrator" -ForegroundColor Gray
Write-Host "   - Automatic UAC elevation will prompt for admin rights" -ForegroundColor Gray
Write-Host "   - Application will self-configure on first run" -ForegroundColor Gray

Write-Host "`n===============================================" -ForegroundColor Green
