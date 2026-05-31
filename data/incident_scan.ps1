Write-Host "========== [1] WEB SERVER / PHP PROCESSES ==========" -ForegroundColor Cyan
$webProcs = Get-Process | Where-Object { $_.ProcessName -match 'httpd|nginx|php|apache|xampp|wamp|mysqld|caddy|lighttpd' }
if ($webProcs) {
    $webProcs | Select-Object Id, ProcessName, Path | Format-Table -AutoSize
} else {
    Write-Host "  No web server or PHP processes found running." -ForegroundColor Green
}

Write-Host "`n========== [2] DEFENDER THREAT DETECTIONS (LAST 15) ==========" -ForegroundColor Cyan
try {
    $threats = Get-MpThreatDetection | Sort-Object InitialDetectionTime -Descending | Select-Object -First 15
    foreach ($t in $threats) {
        Write-Host "  ThreatID: $($t.ThreatID)" -ForegroundColor Yellow
        Write-Host "  Time: $($t.InitialDetectionTime)"
        Write-Host "  ActionSuccess: $($t.ActionSuccess)"
        Write-Host "  Resources: $($t.Resources -join ', ')"
        Write-Host "  ---"
    }
} catch {
    Write-Host "  Could not query Defender detections (may need admin)." -ForegroundColor Red
}

Write-Host "`n========== [3] DEFENDER THREAT CATALOG ==========" -ForegroundColor Cyan
try {
    Get-MpThreat | Sort-Object ActiveSeverity -Descending | Select-Object ThreatID, ThreatName, SeverityID, IsActive, DidThreatExecute | Format-Table -AutoSize
} catch {
    Write-Host "  Could not query Defender threat catalog." -ForegroundColor Red
}

Write-Host "`n========== [4] STARTUP REGISTRY ENTRIES ==========" -ForegroundColor Cyan
$regPaths = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
)
foreach ($rp in $regPaths) {
    Write-Host "  [$rp]" -ForegroundColor Yellow
    try {
        $props = Get-ItemProperty -Path $rp -ErrorAction Stop
        $props.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
            Write-Host "    $($_.Name) = $($_.Value)"
        }
    } catch {
        Write-Host "    (empty or inaccessible)"
    }
}

Write-Host "`n========== [5] SCHEDULED TASKS (SUSPICIOUS) ==========" -ForegroundColor Cyan
$tasks = Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' }
$suspicious = @()
foreach ($task in $tasks) {
    foreach ($action in $task.Actions) {
        if ($action.Execute -match 'php|http|apache|nginx|xampp|wamp|script|powershell.*-enc|cmd.*/c.*http') {
            $suspicious += [PSCustomObject]@{
                TaskName = $task.TaskName
                State    = $task.State
                Execute  = $action.Execute
                Arguments = $action.Arguments
            }
        }
    }
}
if ($suspicious) {
    $suspicious | Format-Table -AutoSize
} else {
    Write-Host "  No suspicious scheduled tasks found." -ForegroundColor Green
}

Write-Host "`n========== [6] RECENTLY MODIFIED PHP FILES (LAST 7 DAYS) ==========" -ForegroundColor Cyan
$phpFiles = Get-ChildItem -Path C:\ -Include *.php -Recurse -ErrorAction SilentlyContinue |
    Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-7) } |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 30
if ($phpFiles) {
    $phpFiles | Select-Object FullName, LastWriteTime, Length | Format-Table -AutoSize
} else {
    Write-Host "  No PHP files modified in the last 7 days." -ForegroundColor Green
}

Write-Host "`n========== [7] LISTENING PORTS WITH PROCESS NAMES ==========" -ForegroundColor Cyan
Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
    Select-Object LocalAddress, LocalPort,
        @{N='ProcessName';E={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}},
        @{N='PID';E={$_.OwningProcess}} |
    Sort-Object LocalPort |
    Format-Table -AutoSize

Write-Host "`n========== SCAN COMPLETE ==========" -ForegroundColor Green
