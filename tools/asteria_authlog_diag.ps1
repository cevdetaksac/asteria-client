# Asteria AuthLog diagnostics — run on lab host (Derin / Ninety)
# Output: %USERPROFILE%\Desktop\asteria_authlog_diag.txt
# Run:
#   powershell -NoProfile -ExecutionPolicy Bypass -File .\asteria_authlog_diag.ps1

$ErrorActionPreference = 'Continue'
$out = Join-Path $env:USERPROFILE 'Desktop\asteria_authlog_diag.txt'

function W([string]$s) {
    Add-Content -LiteralPath $out -Value $s -Encoding UTF8
}

if (Test-Path -LiteralPath $out) {
    Remove-Item -LiteralPath $out -Force
}

W ("=== ASTERIA AUTHLOG DIAG $(Get-Date -Format o) ===")
W ("HOST=$env:COMPUTERNAME  USER=$env:USERNAME")
W ""

W '--- AGENT ---'
Get-Service *asteria*, *Asteria* -ErrorAction SilentlyContinue | ForEach-Object {
    W ("$($_.Name) status=$($_.Status) start=$($_.StartType)")
}
$logs = @(
    Get-ChildItem (Join-Path $env:ProgramData 'Asteria\*.log') -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 5
)
foreach ($lf in $logs) {
    W ("LOGFILE=$($lf.FullName) size=$($lf.Length) mtime=$($lf.LastWriteTime.ToString('o'))")
    Select-String -Path $lf.FullName -Pattern 'AUTHLOG|4\.9\.|auth_log|MySQL \+|ERRORLOG|Access denied|watcher started' -ErrorAction SilentlyContinue |
        Select-Object -Last 50 |
        ForEach-Object { W $_.Line }
}

W ''
W '--- CLIENT GLOB HITS ---'
$mysqlGlobs = @(
    'C:\ProgramData\MySQL\MySQL Server *\Data\*.err',
    'C:\ProgramData\MySQL\MySQL Server *\Data\*.log',
    'C:\Program Files\MySQL\MySQL Server *\data\*.err',
    'C:\Program Files\MySQL\MySQL Server *\data\*.log',
    'C:\Program Files\MariaDB *\data\*.err',
    'C:\ProgramData\MariaDB\*\data\*.err',
    'C:\xampp\mysql\data\*.err',
    'C:\wamp64\bin\mysql\mysql*\data\*.err',
    'C:\laragon\data\mysql*\*.err',
    (Join-Path $env:ProgramData 'Asteria\authlog_probe\mysql\*')
)
$mssqlGlobs = @(
    'C:\Program Files\Microsoft SQL Server\MSSQL*\MSSQL\Log\ERRORLOG',
    'C:\Program Files\Microsoft SQL Server\MSSQL*\MSSQL\Log\ERRORLOG.*',
    'C:\Program Files (x86)\Microsoft SQL Server\MSSQL*\MSSQL\Log\ERRORLOG',
    'C:\Program Files (x86)\Microsoft SQL Server\MSSQL*\MSSQL\Log\ERRORLOG.*',
    (Join-Path $env:ProgramData 'Asteria\authlog_probe\mssql\*')
)
$ftpGlobs = @(
    'C:\inetpub\logs\LogFiles\FTPSVC*\u_ex*.log',
    'C:\inetpub\logs\LogFiles\FTPSVC*\*.log'
)

function Show-Glob([string]$name, [string[]]$patterns) {
    W "[$name]"
    foreach ($g in $patterns) {
        $hits = @(
            Get-ChildItem -Path $g -ErrorAction SilentlyContinue |
                Sort-Object LastWriteTime -Descending |
                Select-Object -First 8
        )
        if ($hits.Count -eq 0) {
            W "  MISS  $g"
            continue
        }
        foreach ($h in $hits) {
            W ("  HIT   $($h.FullName)  len=$($h.Length)  mtime=$($h.LastWriteTime.ToString('o'))")
        }
    }
}

Show-Glob 'MYSQL' $mysqlGlobs
Show-Glob 'MSSQL' $mssqlGlobs
Show-Glob 'FTP' $ftpGlobs

W ''
W '--- MYSQL DISCOVERY ---'
Get-Service *mysql*, *maria* -ErrorAction SilentlyContinue | ForEach-Object {
    W ("$($_.Name) status=$($_.Status) display=$($_.DisplayName)")
}
Get-Process mysqld, mariadbd -ErrorAction SilentlyContinue | ForEach-Object {
    W ("PROC $($_.ProcessName) pid=$($_.Id) path=$($_.Path)")
}

$mysqlExe = @(
    Get-ChildItem 'C:\Program Files\MySQL\MySQL Server *\bin\mysql.exe' -ErrorAction SilentlyContinue
    Get-ChildItem 'C:\Program Files\MariaDB *\bin\mysql.exe' -ErrorAction SilentlyContinue
    Get-Command mysql -ErrorAction SilentlyContinue | ForEach-Object { $_.Source }
) | Select-Object -First 1

if ($mysqlExe) {
    $bin = if ($mysqlExe.FullName) { $mysqlExe.FullName } else { "$mysqlExe" }
    W "mysql.exe=$bin"
    try {
        & $bin -e "SHOW VARIABLES WHERE Variable_name IN ('log_error','datadir','general_log','general_log_file','version','log_error_verbosity');" 2>&1 |
            ForEach-Object { W (($_ | Out-String).TrimEnd()) }
    } catch {
        W ("mysql query ERR $_")
    }
} else {
    W 'mysql.exe NOT FOUND'
}

$candidateRoots = @(
    'C:\ProgramData\MySQL',
    'C:\Program Files\MySQL',
    'C:\Program Files\MariaDB',
    'C:\ProgramData\MariaDB',
    'C:\xampp\mysql',
    'C:\laragon'
) | Where-Object { Test-Path $_ }

foreach ($root in $candidateRoots) {
    Get-ChildItem $root -Recurse -Include *.err, *.log -ErrorAction SilentlyContinue |
        Where-Object { $_.Length -gt 0 -and $_.LastWriteTime -gt (Get-Date).AddDays(-7) } |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 25 |
        ForEach-Object {
            $hits = @(
                Select-String -Path $_.FullName -Pattern 'Access denied' -SimpleMatch -ErrorAction SilentlyContinue |
                    Select-Object -Last 3
            )
            if ($hits.Count -gt 0) {
                W ("DENIED_IN $($_.FullName) mtime=$($_.LastWriteTime.ToString('o'))")
                foreach ($h in $hits) {
                    $line = $h.Line
                    if ($line.Length -gt 240) { $line = $line.Substring(0, 240) }
                    W "  $line"
                }
            }
        }
}

W ''
W '--- MSSQL DISCOVERY ---'
Get-Service 'MSSQL*' -ErrorAction SilentlyContinue | ForEach-Object {
    W ("$($_.Name) status=$($_.Status) display=$($_.DisplayName)")
}
Get-Process sqlservr -ErrorAction SilentlyContinue | ForEach-Object {
    W ("PROC $($_.ProcessName) pid=$($_.Id) path=$($_.Path)")
}

if (Get-Command sqlcmd -ErrorAction SilentlyContinue) {
    W 'sqlcmd local wrong-login:'
    sqlcmd -S localhost -U lab_diag_local -P WrongLocalPass! -Q "SELECT 1" -l 5 -t 5 2>&1 |
        Select-Object -First 10 |
        ForEach-Object { W (($_ | Out-String).TrimEnd()) }
} else {
    W 'sqlcmd missing'
}

Get-ChildItem 'C:\Program Files\Microsoft SQL Server', 'C:\Program Files (x86)\Microsoft SQL Server' -Recurse -Filter 'ERRORLOG' -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 10 |
    ForEach-Object {
        W ("ERRORLOG=$($_.FullName) mtime=$($_.LastWriteTime.ToString('o')) len=$($_.Length)")
        Select-String -Path $_.FullName -Pattern 'Login failed|CLIENT:' -ErrorAction SilentlyContinue |
            Select-Object -Last 8 |
            ForEach-Object {
                $line = $_.Line
                if ($line.Length -gt 240) { $line = $line.Substring(0, 240) }
                W "  $line"
            }
    }

W ''
W '--- LISTEN 3306/1433 ---'
Get-NetTCPConnection -State Listen -LocalPort 3306, 1433 -ErrorAction SilentlyContinue | ForEach-Object {
    $p = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
    W ("$($_.LocalAddress):$($_.LocalPort) pid=$($_.OwningProcess) name=$($p.ProcessName) path=$($p.Path)")
}

W ''
W ("ASTERIA_AUTHLOG_EXTRA=$env:ASTERIA_AUTHLOG_EXTRA")
W '=== END DIAG ==='

Write-Host ""
Write-Host "DONE -> $out"
Write-Host "Paste that TXT contents into Cursor chat."
Start-Process notepad.exe $out
