# Migrate durable agent state from YesNext → %ProgramData%\Asteria
param(
    [switch]$Force
)

$ErrorActionPreference = "Continue"
$dest = Join-Path $env:ProgramData "Asteria"
$marker = Join-Path $dest ".migrated_from_yesnext"

New-Item -ItemType Directory -Force -Path $dest | Out-Null

if (-not $Force -and (Test-Path -LiteralPath $marker)) {
    Write-Host "[MIGRATE] Already migrated → $dest"
    exit 0
}

$sources = @(
    (Join-Path $env:ProgramData "YesNext\CloudHoneypotClient"),
    (Join-Path $env:ProgramData "YesNext\CloudHoneypot")
)
if ($env:APPDATA) {
    $sources += (Join-Path $env:APPDATA "YesNext\CloudHoneypotClient")
}

$copied = 0
$skipped = 0
$used = @()

foreach ($src in $sources) {
    if (-not (Test-Path -LiteralPath $src)) { continue }
    $used += $src
    Get-ChildItem -LiteralPath $src -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
        $rel = $_.FullName.Substring($src.Length).TrimStart('\')
        if ([string]::IsNullOrWhiteSpace($rel)) { return }
        $target = Join-Path $dest $rel
        $parent = Split-Path -Parent $target
        if (-not (Test-Path -LiteralPath $parent)) {
            New-Item -ItemType Directory -Force -Path $parent | Out-Null
        }
        if (Test-Path -LiteralPath $target) {
            try {
                if ($_.LastWriteTimeUtc -le (Get-Item -LiteralPath $target).LastWriteTimeUtc) {
                    $script:skipped++
                    return
                }
            } catch {
                $script:skipped++
                return
            }
        }
        try {
            Copy-Item -LiteralPath $_.FullName -Destination $target -Force
            $script:copied++
        } catch {
            $script:skipped++
        }
    }
}

@(
    "migrated_at=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))",
    "copied=$copied",
    "skipped=$skipped",
    "sources=$($used -join ';')"
) | Set-Content -LiteralPath $marker -Encoding UTF8

# Allow Users to write agent state (token/logs/lock) under ProgramData\Asteria
try {
    icacls $dest /inheritance:r `
        /grant:r "NT AUTHORITY\SYSTEM:(OI)(CI)F" `
        /grant:r "BUILTIN\Administrators:(OI)(CI)F" `
        /grant:r "BUILTIN\Users:(OI)(CI)M" `
        /C /Q | Out-Null
    icacls "$dest\*" /inheritance:e /T /C /Q | Out-Null
} catch {}

Write-Host "[MIGRATE] copied=$copied skipped=$skipped dest=$dest"
exit 0
