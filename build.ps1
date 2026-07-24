# Asteria Client - Build Script
# Version is read automatically from client_constants.py (single source of truth)

param(
    [switch]$Clean = $false,
    [switch]$WebRTC = $false,
    [switch]$Sign = $false,
    [string]$CertPath = $env:HONEYPOT_SIGN_CERT,
    [string]$CertPassword = $env:HONEYPOT_SIGN_CERT_PASSWORD,
    [string]$TimestampUrl = "http://timestamp.digicert.com"
)

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
    Remove-Item -Path "cloud-client-installer.exe" -Force -ErrorAction SilentlyContinue
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

# Step 3: Check for NSIS
Write-Host "[3/5] Checking for NSIS..." -ForegroundColor Yellow
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

# Step 4: Build installer
Write-Host "[4/5] Building installer..." -ForegroundColor Yellow
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

# Step 5: Optional Authenticode + provenance (SUP-001 / SUP-002)
Write-Host "`n[5/6] Signing / provenance..." -ForegroundColor Yellow
$installerPath = Join-Path (Get-Location) "cloud-client-installer.exe"
$mainExe = Join-Path (Get-Location) "dist\asteria-client\asteria-client.exe"
$signed = $false
if ($Sign) {
    if (-not $CertPath -or -not (Test-Path $CertPath)) {
        Write-Host "   ERROR: -Sign requires CertPath / HONEYPOT_SIGN_CERT" -ForegroundColor Red
        exit 1
    }
    $signtool = Get-Command signtool.exe -ErrorAction SilentlyContinue
    if (-not $signtool) {
        Write-Host "   ERROR: signtool.exe not found in PATH" -ForegroundColor Red
        exit 1
    }
    $targets = @($mainExe, $installerPath) | Where-Object { $_ -and (Test-Path $_) }
    foreach ($target in $targets) {
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
    $signed = $true
} else {
    Write-Host "   SKIP: Authenticode (-Sign not set; unsigned build OK for dev)" -ForegroundColor DarkGray
}

# Step 6: Show results + emit provenance manifest
Write-Host "`n[6/6] Build completed successfully!" -ForegroundColor Green
Write-Host "===============================================" -ForegroundColor Green

$installerFile = Get-Item "cloud-client-installer.exe" -ErrorAction SilentlyContinue
if ($installerFile) {
    $sizeMB = [math]::Round($installerFile.Length / 1MB, 1)
    $sha = (Get-FileHash -Algorithm SHA256 -Path $installerFile.FullName).Hash.ToLowerInvariant()
    $provenance = [ordered]@{
        product = "asteria-client"
        version = $VERSION
        artifact = "cloud-client-installer.exe"
        sha256 = $sha
        size_bytes = $installerFile.Length
        built_at = (Get-Date).ToUniversalTime().ToString("o")
        webrtc = [bool]$WebRTC
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
    Write-Host ("Installer: cloud-client-installer.exe ({0} MB)" -f $sizeMB) -ForegroundColor Cyan
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
Write-Host "   - Run cloud-client-installer.exe as Administrator" -ForegroundColor Gray
Write-Host "   - Automatic UAC elevation will prompt for admin rights" -ForegroundColor Gray
Write-Host "   - Application will self-configure on first run" -ForegroundColor Gray

Write-Host "`n===============================================" -ForegroundColor Green
