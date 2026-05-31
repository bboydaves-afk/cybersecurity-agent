Write-Host "========== [1] WINDOWS DEFENDER STATUS ==========" -ForegroundColor Cyan
try {
    $mpStatus = Get-MpComputerStatus
    Write-Host "  Real-time Protection:   $($mpStatus.RealTimeProtectionEnabled)"
    Write-Host "  Behavior Monitoring:    $($mpStatus.BehaviorMonitorEnabled)"
    Write-Host "  On-Access Protection:   $($mpStatus.OnAccessProtectionEnabled)"
    Write-Host "  Network Protection:     $($mpStatus.IoavProtectionEnabled)"
    Write-Host "  Tamper Protection:      $($mpStatus.IsTamperProtected)"
    Write-Host "  Cloud Protection:       $($mpStatus.MAPSReporting)"
    Write-Host "  Antivirus Sig Version:  $($mpStatus.AntivirusSignatureVersion)"
    Write-Host "  Antivirus Sig Updated:  $($mpStatus.AntivirusSignatureLastUpdated)"
    Write-Host "  Last Quick Scan:        $($mpStatus.QuickScanStartTime)"
    Write-Host "  Last Full Scan:         $($mpStatus.FullScanStartTime)"
} catch {
    Write-Host "  Could not query Defender status." -ForegroundColor Red
}

Write-Host "`n========== [2] WINDOWS FIREWALL STATUS ==========" -ForegroundColor Cyan
try {
    $profiles = Get-NetFirewallProfile
    foreach ($p in $profiles) {
        $status = if ($p.Enabled) { "ENABLED" } else { "DISABLED" }
        $color = if ($p.Enabled) { "Green" } else { "Red" }
        Write-Host "  $($p.Name) Profile: $status (Default Inbound: $($p.DefaultInboundAction), Outbound: $($p.DefaultOutboundAction))" -ForegroundColor $color
    }
} catch {
    Write-Host "  Could not query firewall." -ForegroundColor Red
}

Write-Host "`n========== [3] WINDOWS UPDATE STATUS ==========" -ForegroundColor Cyan
try {
    $lastInstall = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1
    Write-Host "  Last Update Installed:  $($lastInstall.InstalledOn) ($($lastInstall.HotFixID))"
    $daysSince = ((Get-Date) - $lastInstall.InstalledOn).Days
    $color = if ($daysSince -gt 30) { "Red" } elseif ($daysSince -gt 14) { "Yellow" } else { "Green" }
    Write-Host "  Days Since Last Update: $daysSince" -ForegroundColor $color
} catch {
    Write-Host "  Could not query update history." -ForegroundColor Red
}

Write-Host "`n========== [4] USER ACCOUNTS ==========" -ForegroundColor Cyan
try {
    $users = Get-LocalUser
    foreach ($u in $users) {
        $status = if ($u.Enabled) { "Enabled" } else { "Disabled" }
        $color = if ($u.Enabled) { "Yellow" } else { "DarkGray" }
        Write-Host "  $($u.Name) - $status (LastLogon: $($u.LastLogon))" -ForegroundColor $color
    }
} catch {
    Write-Host "  Could not query local users." -ForegroundColor Red
}

Write-Host "`n========== [5] ADMIN GROUP MEMBERS ==========" -ForegroundColor Cyan
try {
    $admins = Get-LocalGroupMember -Group "Administrators"
    foreach ($a in $admins) {
        Write-Host "  $($a.Name) ($($a.ObjectClass))" -ForegroundColor Yellow
    }
} catch {
    Write-Host "  Could not query admin group." -ForegroundColor Red
}

Write-Host "`n========== [6] UAC STATUS ==========" -ForegroundColor Cyan
try {
    $uac = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    $level = switch ($uac.ConsentPromptBehaviorAdmin) {
        0 { "DISABLED (no prompt)" }
        1 { "Prompt for credentials on secure desktop" }
        2 { "Prompt for consent on secure desktop" }
        3 { "Prompt for credentials" }
        4 { "Prompt for consent" }
        5 { "Prompt for consent (non-Windows binaries)" }
        default { "Unknown ($($uac.ConsentPromptBehaviorAdmin))" }
    }
    $enabled = if ($uac.EnableLUA -eq 1) { "ENABLED" } else { "DISABLED" }
    Write-Host "  UAC Enabled: $enabled"
    Write-Host "  Admin Prompt: $level"
} catch {
    Write-Host "  Could not query UAC." -ForegroundColor Red
}

Write-Host "`n========== [7] BITLOCKER STATUS ==========" -ForegroundColor Cyan
try {
    $bl = Get-BitLockerVolume -MountPoint C: -ErrorAction Stop
    Write-Host "  C: Drive Protection: $($bl.ProtectionStatus)"
    Write-Host "  Encryption Method:   $($bl.EncryptionMethod)"
    Write-Host "  Volume Status:       $($bl.VolumeStatus)"
} catch {
    Write-Host "  BitLocker status unavailable (may need admin or not supported)." -ForegroundColor Yellow
}

Write-Host "`n========== [8] SMB SHARES ==========" -ForegroundColor Cyan
try {
    $shares = Get-SmbShare | Where-Object { $_.Name -notmatch '^\$' -and $_.Name -ne 'IPC$' }
    if ($shares) {
        foreach ($s in $shares) {
            Write-Host "  $($s.Name) -> $($s.Path) (Description: $($s.Description))" -ForegroundColor Yellow
        }
    } else {
        Write-Host "  No custom SMB shares (only default admin shares)." -ForegroundColor Green
    }
} catch {
    Write-Host "  Could not query SMB shares." -ForegroundColor Red
}

Write-Host "`n========== [9] RDP STATUS ==========" -ForegroundColor Cyan
try {
    $rdp = Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server'
    $rdpStatus = if ($rdp.fDenyTSConnections -eq 1) { "DISABLED" } else { "ENABLED" }
    $color = if ($rdp.fDenyTSConnections -eq 1) { "Green" } else { "Yellow" }
    Write-Host "  Remote Desktop: $rdpStatus" -ForegroundColor $color
} catch {
    Write-Host "  Could not query RDP status." -ForegroundColor Red
}

Write-Host "`n========== [10] NETWORK EXPOSURE (0.0.0.0 LISTENERS) ==========" -ForegroundColor Cyan
$exposed = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
    Where-Object { $_.LocalAddress -eq '0.0.0.0' -or $_.LocalAddress -eq '::' } |
    Where-Object { $_.LocalPort -lt 49664 } |
    Select-Object LocalPort,
        @{N='Process';E={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}},
        @{N='PID';E={$_.OwningProcess}} |
    Sort-Object LocalPort -Unique
if ($exposed) {
    $exposed | Format-Table -AutoSize
} else {
    Write-Host "  No services exposed on all interfaces." -ForegroundColor Green
}

Write-Host "`n========== [11] RECENTLY INSTALLED SOFTWARE (LAST 30 DAYS) ==========" -ForegroundColor Cyan
try {
    $recent = Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*,
        HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* -ErrorAction SilentlyContinue |
        Where-Object { $_.InstallDate -and $_.InstallDate -gt (Get-Date).AddDays(-30).ToString('yyyyMMdd') } |
        Sort-Object InstallDate -Descending |
        Select-Object DisplayName, DisplayVersion, InstallDate -First 15
    if ($recent) {
        $recent | Format-Table -AutoSize
    } else {
        Write-Host "  No new software installed in the last 30 days." -ForegroundColor Green
    }
} catch {
    Write-Host "  Could not query installed software." -ForegroundColor Red
}

Write-Host "`n========== [12] POWERSHELL EXECUTION POLICY ==========" -ForegroundColor Cyan
try {
    $policies = Get-ExecutionPolicy -List
    foreach ($p in $policies) {
        Write-Host "  $($p.Scope): $($p.ExecutionPolicy)"
    }
} catch {
    Write-Host "  Could not query execution policy." -ForegroundColor Red
}

Write-Host "`n========== [13] CREDENTIAL GUARD / SECURE BOOT ==========" -ForegroundColor Cyan
try {
    $secureBoot = Confirm-SecureBootUEFI -ErrorAction Stop
    Write-Host "  Secure Boot: $secureBoot" -ForegroundColor $(if ($secureBoot) { 'Green' } else { 'Red' })
} catch {
    Write-Host "  Secure Boot: Could not determine" -ForegroundColor Yellow
}
try {
    $dg = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction Stop
    if ($dg.SecurityServicesRunning -contains 1) {
        Write-Host "  Credential Guard: RUNNING" -ForegroundColor Green
    } else {
        Write-Host "  Credential Guard: NOT RUNNING" -ForegroundColor Yellow
    }
} catch {
    Write-Host "  Credential Guard: Could not determine" -ForegroundColor Yellow
}

Write-Host "`n========== SECURITY AUDIT COMPLETE ==========" -ForegroundColor Green
