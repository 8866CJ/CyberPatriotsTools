<#
  CyberPatriot Hardening Toolkit
  Windows 10/11 and Windows Server 2016+. Native PowerShell 5.1, no modules to install.

  Run:  powershell -ExecutionPolicy Bypass -File .\CyberPatriot-Toolkit.ps1
  READ THE README FIRST. Do the forensics questions BEFORE deleting files or users.
  Anything destructive asks first. Every change is written to the log file next to this script.
#>

# --- self-elevate -------------------------------------------------------------
$me = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $me.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

$ErrorActionPreference = 'Continue'
$Here = if ($PSScriptRoot) { $PSScriptRoot } else { $PWD.Path }
$Log  = Join-Path $Here ("cp-log-{0:yyyyMMdd-HHmmss}.txt" -f (Get-Date))
$OS   = Get-CimInstance Win32_OperatingSystem
$IsDC = $OS.ProductType -eq 2

# --- output helpers -----------------------------------------------------------
function Say($m, $c = 'Gray') { Write-Host $m -ForegroundColor $c }
function Ok($m)   { Say "  [+] $m" Green;  Add-Content $Log "[+] $m" }
function Warn($m) { Say "  [!] $m" Yellow; Add-Content $Log "[!] $m" }
function Info($m) { Say "  [*] $m" Cyan }
function Head($m) { Say "`n  --- $m ---" Magenta }
function Ask($q)  { (Read-Host "  $q [y/N]") -match '^\s*y' }
function Read-List($prompt) {
    @((Read-Host "  $prompt (comma/space separated)") -split '[,;\s]+' | Where-Object { $_ })
}

# Numbered picker: returns the items the user selected ("1,3,5-8", "all", or Enter for none).
function Select-Items($Items, [scriptblock]$Label) {
    $Items = @($Items | Where-Object { $_ })
    if (-not $Items.Count) { Say '  (none found)' DarkGray; return }
    for ($i = 0; $i -lt $Items.Count; $i++) { Say ("  {0,3}) {1}" -f ($i + 1), ($Items[$i] | ForEach-Object $Label)) }
    $s = Read-Host '  Select (e.g. 1,3,5-8 / all / Enter = none)'
    $idx = if ($s -eq 'all') { 0..($Items.Count - 1) } else {
        foreach ($p in $s -split ',') {
            if ($p -match '^\s*(\d+)\s*(?:-\s*(\d+))?\s*$') {
                $a = [int]$matches[1]; $b = if ($matches[2]) { [int]$matches[2] } else { $a }
                ($a - 1)..($b - 1)
            }
        }
    }
    $idx | Where-Object { $_ -ge 0 -and $_ -lt $Items.Count } | Sort-Object -Unique | ForEach-Object { $Items[$_] }
}

function Set-Reg($Path, $Name, $Value, $Label, $Type = 'DWord') {
    try {
        if (-not (Test-Path $Path)) { New-Item $Path -Force | Out-Null }
        New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $Type -Force -ErrorAction Stop | Out-Null
        Ok $(if ($Label) { $Label } else { "$Name = $Value" })
    } catch { Warn "$Name : $($_.Exception.Message)" }
}

# Edits [System Access] in the local security policy (password/lockout/guest/anon settings).
function Set-SecPolicy([hashtable]$Settings) {
    $inf = Join-Path $env:TEMP 'cp-secpol.inf'; $sdb = Join-Path $env:TEMP 'cp-secpol.sdb'
    secedit /export /cfg $inf /areas SECURITYPOLICY /quiet | Out-Null
    $lines = [Collections.Generic.List[string]](Get-Content $inf)
    $at = $lines.IndexOf('[System Access]')
    foreach ($k in $Settings.Keys) {
        $line = "$k = $($Settings[$k])"; $found = $false
        for ($j = 0; $j -lt $lines.Count; $j++) { if ($lines[$j] -match "^$k\s*=") { $lines[$j] = $line; $found = $true; break } }
        if (-not $found) { $lines.Insert($at + 1, $line) }
    }
    $lines | Set-Content $inf -Encoding Unicode
    secedit /configure /db $sdb /cfg $inf /areas SECURITYPOLICY /quiet | Out-Null
    if ($LASTEXITCODE -eq 0) { $Settings.Keys | ForEach-Object { Ok "$_ = $($Settings[$_])" } } else { Warn "secedit failed ($LASTEXITCODE)" }
    Remove-Item $inf, $sdb -ErrorAction SilentlyContinue
}

# Group names resolved by SID so non-English images work too.
$AdminGrp = (Get-LocalGroup -SID 'S-1-5-32-544' -ErrorAction SilentlyContinue).Name
$UsersGrp = (Get-LocalGroup -SID 'S-1-5-32-545' -ErrorAction SilentlyContinue).Name

# ADSI instead of Get-LocalGroupMember: the latter breaks on orphaned SIDs (common on CP images).
function Get-GroupMembers($g) {
    try {
        @(([ADSI]"WinNT://$env:COMPUTERNAME/$g,group").psbase.Invoke('Members') |
            ForEach-Object { $_.GetType().InvokeMember('Name', 'GetProperty', $null, $_, $null) })
    } catch { @() }
}

function Sync-Group($g, $want, $keep = @()) {
    $have = Get-GroupMembers $g
    foreach ($m in $have) {
        if ($m -notin $want -and $m -notin $keep -and (Ask "'$m' should NOT be in '$g' - remove?")) {
            net localgroup "$g" "$m" /delete | Out-Null
            if ($LASTEXITCODE -eq 0) { Ok "Removed $m from $g" } else { Warn "Could not remove $m from $g" }
        }
    }
    foreach ($m in $want) {
        if ($m -notin $have -and (Ask "'$m' is missing from '$g' - add?")) {
            net localgroup "$g" "$m" /add | Out-Null
            if ($LASTEXITCODE -eq 0) { Ok "Added $m to $g" } else { Warn "Could not add $m to $g" }
        }
    }
}

# ==============================================================================
# 1. Users
# ==============================================================================
function Invoke-UserAudit {
    if ($IsDC) { Warn 'Domain controller: manage users with Active Directory Users and Computers (dsa.msc).'; return }
    Head 'Current local users'
    Get-LocalUser | Format-Table Name, Enabled, PasswordRequired, PasswordExpires, LastLogon, Description -AutoSize | Out-String -Width 220 | Write-Host
    Info "Administrators: $((Get-GroupMembers $AdminGrp) -join ', ')"

    Info "You are '$env:USERNAME' - you are always kept."
    $admins = Read-List 'Authorized ADMINISTRATORS from README'
    $users  = Read-List 'Authorized standard USERS from README'
    $all    = @($admins + $users + $env:USERNAME) | Sort-Object -Unique
    $builtin = Get-LocalUser | Where-Object { $_.SID.Value -match '-(500|501|503|504)$' }  # Administrator, Guest, DefaultAccount, WDAG

    Head 'Unauthorized users'
    foreach ($u in Get-LocalUser) {
        if ($u.Name -in $all -or $u.Name -in $builtin.Name) { continue }
        if (Ask "Unauthorized user '$($u.Name)' - DELETE?") { Remove-LocalUser -Name $u.Name; Ok "Removed unauthorized user $($u.Name)" }
    }

    Head 'Missing users'
    $pw = $null
    foreach ($n in $all) {
        if (Get-LocalUser -Name $n -ErrorAction SilentlyContinue) { continue }
        if (Ask "User '$n' is in the README but missing - create?") {
            if (-not $pw) { $pw = Read-Host '  Password for new/reset accounts' -AsSecureString }
            New-LocalUser -Name $n -Password $pw | Out-Null
            net localgroup "$UsersGrp" "$n" /add | Out-Null
            Ok "Created user account $n"
        }
    }

    Head 'Administrators group'
    Sync-Group $AdminGrp @($admins + $env:USERNAME) @(($builtin | Where-Object { $_.SID.Value -match '-500$' }).Name, 'Domain Admins')

    Head 'Account settings'
    if (Ask 'Set a secure password + fix flags (expires, required, can change) on all authorized users except you?') {
        if (-not $pw) { $pw = Read-Host '  Password for new/reset accounts' -AsSecureString }
        foreach ($n in $all | Where-Object { $_ -ne $env:USERNAME }) {
            if (-not (Get-LocalUser -Name $n -ErrorAction SilentlyContinue)) { continue }
            Set-LocalUser -Name $n -Password $pw -PasswordNeverExpires $false -UserMayChangePassword $true
            net user "$n" /passwordreq:yes | Out-Null
            Ok "Secured account $n"
        }
    }
    foreach ($n in $all) {
        $u = Get-LocalUser -Name $n -ErrorAction SilentlyContinue
        if ($u -and -not $u.Enabled -and (Ask "Authorized user '$n' is disabled - enable?")) { Enable-LocalUser $n; Ok "Enabled $n" }
    }
    foreach ($b in $builtin) {
        if ($b.Enabled -and $b.Name -ne $env:USERNAME) { Disable-LocalUser $b.Name; Ok "Disabled built-in account $($b.Name)" }
    }
}

# ==============================================================================
# 2. Groups
# ==============================================================================
function Edit-Groups {
    if ($IsDC) { Warn 'Domain controller: edit groups in dsa.msc.'; return }
    Get-LocalGroup | ForEach-Object {
        $m = Get-GroupMembers $_.Name
        if ($m) { Say ("  {0,-34} {1}" -f $_.Name, ($m -join ', ')) }
    }
    while ($g = Read-Host "`n  Group to edit (e.g. Remote Desktop Users, Enter = back)") {
        if (-not (Get-LocalGroup -Name $g -ErrorAction SilentlyContinue)) {
            if (Ask "Group '$g' does not exist - create?") { New-LocalGroup -Name $g | Out-Null; Ok "Created group $g" } else { continue }
        }
        Info "Now: $((Get-GroupMembers $g) -join ', ')"
        Sync-Group $g (Read-List "Exact members the README wants in '$g'")
    }
}

# ==============================================================================
# 3. Password + lockout policy
# ==============================================================================
function Set-PasswordPolicy {
    if ($IsDC) { Warn 'DC: domain policy (gpmc.msc > Default Domain Policy) overrides this. Applying locally anyway.' }
    Set-SecPolicy @{
        MinimumPasswordAge    = 1;  MaximumPasswordAge = 60; MinimumPasswordLength = 12
        PasswordComplexity    = 1;  PasswordHistorySize = 24; ClearTextPassword = 0
        LockoutBadCount       = 5;  LockoutDuration = 30; ResetLockoutCount = 30
        EnableGuestAccount    = 0;  LSAAnonymousNameLookup = 0
    }
    net accounts | Write-Host
}

# ==============================================================================
# 4. Security options (registry)
# ==============================================================================
function Set-SecurityOptions {
    $lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    $sys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    $srv = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
    $wks = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'
    $exp = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
    $wl  = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    @(
        @($lsa, 'LimitBlankPasswordUse', 1, 'Limit local use of blank passwords to console only'),
        @($lsa, 'RestrictAnonymousSAM', 1, 'Do not allow anonymous enumeration of SAM accounts'),
        @($lsa, 'RestrictAnonymous', 1, 'Do not allow anonymous enumeration of SAM accounts and shares'),
        @($lsa, 'EveryoneIncludesAnonymous', 0, 'Everyone permissions do not apply to anonymous'),
        @($lsa, 'NoLMHash', 1, 'Do not store LAN Manager hash'),
        @($lsa, 'LmCompatibilityLevel', 5, 'NTLMv2 only, refuse LM & NTLM'),
        @($lsa, 'SCENoApplyLegacyAuditPolicy', 1, 'Audit subcategory settings override categories'),
        @($lsa, 'RunAsPPL', 1, 'LSA protection'),
        @('HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest', 'UseLogonCredential', 0, 'WDigest plaintext creds off'),
        @($srv, 'RestrictNullSessAccess', 1, 'Restrict anonymous access to pipes/shares'),
        @($srv, 'RequireSecuritySignature', 1, 'SMB server: always sign'),
        @($srv, 'EnableSecuritySignature', 1, 'SMB server: sign if client agrees'),
        @($srv, 'SMB1', 0, 'SMBv1 server off'),
        @($wks, 'RequireSecuritySignature', 1, 'SMB client: always sign'),
        @($wks, 'EnablePlainTextPassword', 0, 'No unencrypted passwords to SMB servers'),
        @($sys, 'EnableLUA', 1, 'UAC on'),
        @($sys, 'ConsentPromptBehaviorAdmin', 2, 'UAC: prompt admins on secure desktop'),
        @($sys, 'ConsentPromptBehaviorUser', 0, 'UAC: auto-deny elevation for standard users'),
        @($sys, 'PromptOnSecureDesktop', 1, 'UAC: secure desktop'),
        @($sys, 'EnableInstallerDetection', 1, 'UAC: detect installers'),
        @($sys, 'FilterAdministratorToken', 1, 'UAC: admin approval mode for built-in Administrator'),
        @($sys, 'LocalAccountTokenFilterPolicy', 0, 'Remote UAC filtering on'),
        @($sys, 'DontDisplayLastUserName', 1, 'Do not display last signed-in user'),
        @($sys, 'DisableCAD', 0, 'Require CTRL+ALT+DEL'),
        @($sys, 'InactivityTimeoutSecs', 900, 'Machine inactivity limit 15 min'),
        @($exp, 'NoDriveTypeAutoRun', 255, 'AutoPlay off on all drives'),
        @($exp, 'NoAutorun', 1, 'AutoRun off'),
        @($wl, 'AutoAdminLogon', '0', 'Automatic logon off', 'String'),
        @('HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer', 'AlwaysInstallElevated', 0, 'AlwaysInstallElevated off (HKLM)'),
        @('HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer', 'AlwaysInstallElevated', 0, 'AlwaysInstallElevated off (HKCU)'),
        @('HKLM:\SOFTWARE\Policies\Microsoft\Windows\System', 'EnableSmartScreen', 1, 'SmartScreen on')
    ) | ForEach-Object { Set-Reg @_ }

    if ((Get-ItemProperty $wl -ErrorAction SilentlyContinue).DefaultPassword) {
        Remove-ItemProperty $wl -Name DefaultPassword; Ok 'Removed plaintext autologon password (Winlogon\DefaultPassword)'
    }
    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction SilentlyContinue
    Info 'Some options apply after reboot / re-login.'
}

# ==============================================================================
# 5. Firewall, Defender, auditing
# ==============================================================================
function Set-Protection {
    sc.exe config MpsSvc start= auto | Out-Null; Start-Service MpsSvc -ErrorAction SilentlyContinue
    Set-NetFirewallProfile -All -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow -NotifyOnListen True -LogBlocked True
    Ok 'Firewall protection has been enabled (all profiles)'

    Remove-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' -Name DisableAntiSpyware, DisableAntiVirus -ErrorAction SilentlyContinue
    Remove-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection' -Name DisableRealtimeMonitoring, DisableBehaviorMonitoring, DisableOnAccessProtection, DisableIOAVProtection -ErrorAction SilentlyContinue
    if (Get-Command Set-MpPreference -ErrorAction SilentlyContinue) {
        Set-MpPreference -DisableRealtimeMonitoring $false -DisableBehaviorMonitoring $false -DisableIOAVProtection $false `
            -DisableScriptScanning $false -PUAProtection Enabled -MAPSReporting Advanced -ErrorAction SilentlyContinue
        Ok 'Defender real-time / behavior / PUA protection on'
        $p = Get-MpPreference
        foreach ($t in 'Path', 'Process', 'Extension') {
            $v = $p."Exclusion$t"
            if ($v) {
                $v | ForEach-Object { Warn "Defender exclusion ($t): $_" }
                if (Ask "Remove these $t exclusions?") { $h = @{ "Exclusion$t" = $v }; Remove-MpPreference @h; Ok "Removed Defender $t exclusions" }
            }
        }
        Info 'Updating Defender signatures...'; Update-MpSignature -ErrorAction SilentlyContinue
        if (Ask 'Run a Defender quick scan now?') { Start-MpScan -ScanType QuickScan; Ok 'Quick scan done' }
    } else { Warn 'Defender cmdlets not present (Defender removed?).' }

    auditpol /set /category:* /success:enable /failure:enable | Out-Null
    Ok 'Auditing: success + failure for all categories'
}

# ==============================================================================
# 6. Remote access
# ==============================================================================
function Set-RemoteAccess {
    Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' fAllowToGetHelp 0 'Remote Assistance connections disabled'
    Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' fAllowFullControl 0 'Remote Assistance control disabled'

    $ts = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
    $rdpRules = '@FirewallAPI.dll,-28752'   # "Remote Desktop" rule group, language independent
    switch -Regex (Read-Host '  Is Remote Desktop REQUIRED by the README? (y/n/Enter = leave as is)') {
        '^y' {
            Set-Reg $ts fDenyTSConnections 0 'Remote Desktop enabled'
            Enable-NetFirewallRule -Group $rdpRules -ErrorAction SilentlyContinue
            sc.exe config TermService start= auto | Out-Null; Start-Service TermService -ErrorAction SilentlyContinue
            Info "Use menu 2 to set 'Remote Desktop Users' to exactly who the README lists."
        }
        '^n' {
            Set-Reg $ts fDenyTSConnections 1 'Remote Desktop disabled'
            Disable-NetFirewallRule -Group $rdpRules -ErrorAction SilentlyContinue
            if (Ask 'Also stop & disable the Remote Desktop service (TermService)?') {
                Stop-Service TermService -Force -ErrorAction SilentlyContinue; sc.exe config TermService start= disabled | Out-Null; Ok 'TermService disabled'
            }
        }
    }
    $rdp = "$ts\WinStations\RDP-Tcp"
    Set-Reg $rdp UserAuthentication 1 'RDP network level authentication enabled'
    Set-Reg $rdp SecurityLayer 2 'RDP security layer: TLS'
    Set-Reg $rdp MinEncryptionLevel 3 'RDP encryption: high'
}

# ==============================================================================
# 7. Services
# ==============================================================================
$BadServices = [ordered]@{
    ftpsvc = 'FTP'; TlntSvr = 'Telnet'; sshd = 'OpenSSH Server'; SNMP = 'SNMP'; SNMPTRAP = 'SNMP Trap'
    RemoteRegistry = 'Remote Registry'; SSDPSRV = 'SSDP Discovery'; upnphost = 'UPnP Device Host'
    SharedAccess = 'Internet Connection Sharing'; RemoteAccess = 'Routing and Remote Access'; RasAuto = 'RAS Auto Connection'
    simptcp = 'Simple TCP/IP'; W3SVC = 'IIS Web Server'; WMSvc = 'IIS Web Management'; SMTPSVC = 'SMTP'
    WinRM = 'Windows Remote Management'; WebClient = 'WebDAV Client'; Spooler = 'Print Spooler'; Fax = 'Fax'
    icssvc = 'Mobile Hotspot'; lfsvc = 'Geolocation'; MapsBroker = 'Maps Manager'; NetTcpPortSharing = 'Net.Tcp Port Sharing'
    XblAuthManager = 'Xbox Auth'; XblGameSave = 'Xbox Game Save'; XboxNetApiSvc = 'Xbox Networking'; XboxGipSvc = 'Xbox Accessories'
}
$GoodServices = 'wuauserv', 'WinDefend', 'MpsSvc', 'BFE', 'EventLog', 'wscsvc', 'Dnscache'

function Set-Services {
    Info 'Keep anything the README says is a critical service!'
    foreach ($name in $BadServices.Keys) {
        $s = Get-Service $name -ErrorAction SilentlyContinue
        if (-not $s) { continue }
        $label = $BadServices[$name]
        if ($s.Status -eq 'Stopped' -and $s.StartType -eq 'Disabled') { Say "  [=] $label already disabled" DarkGray; continue }
        if (Ask "$label ($name) is $($s.Status)/$($s.StartType) - stop & disable?") {
            Stop-Service $name -Force -ErrorAction SilentlyContinue
            sc.exe config $name start= disabled | Out-Null
            if ($LASTEXITCODE -eq 0) { Ok "$label service has been stopped and disabled" } else { Warn "Could not disable $name" }
        }
    }
    Head 'Required services'
    foreach ($name in $GoodServices) {
        $s = Get-Service $name -ErrorAction SilentlyContinue
        if (-not $s) { continue }
        if ($s.StartType -eq 'Disabled') { sc.exe config $name start= auto | Out-Null }
        if ($s.Status -ne 'Running') { Start-Service $name -ErrorAction SilentlyContinue }
        $s.Refresh()
        if ($s.Status -eq 'Running') { Say "  [=] $name running" DarkGreen } else { Warn "$name is $($s.Status) - check manually" }
    }
    Head 'Non-Windows services (look for backdoors / unknown names)'
    Get-CimInstance Win32_Service |
        Where-Object { $_.PathName -and $_.PathName -notmatch '\\Windows\\(system32|SysWOW64|Microsoft\.NET|servicing)\\|Windows Defender' } |
        Format-Table Name, State, StartMode, PathName -AutoSize | Out-String -Width 220 | Write-Host
}

# ==============================================================================
# 8. Software
# ==============================================================================
$BadSoftware = 'wireshark|npcap|winpcap|ccleaner|nmap|zenmap|\bcain\b|john the ripper|hashcat|ophcrack|l0phtcrack|metasploit|' +
    'angry ip|advanced ip scanner|netstumbler|nessus|burp|hydra|netcat|ncat|aircrack|cheat engine|mimikatz|' +
    'utorrent|bittorrent|qbittorrent|vuze|frostwire|limewire|shareaza|deluge|tor browser|' +
    'teamviewer|anydesk|tightvnc|realvnc|ultravnc|ammyy|radmin|remote utilities|' +
    'advanced systemcare|driver booster|pc cleaner|steam|epic games|minecraft|roblox'

function Get-Installed {
    Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
                     'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
                     'Registry::HKEY_USERS\*\Software\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -and $_.UninstallString -and -not $_.SystemComponent } |
        Sort-Object DisplayName -Unique
}

function Remove-BadSoftware {
    $all = Get-Installed
    Head "All installed programs ($(@($all).Count)) - compare with README"
    $all | ForEach-Object { Say ("  {0,-55} {1,-18} {2}" -f $_.DisplayName, $_.DisplayVersion, $_.Publisher) DarkGray }

    Head 'Flagged programs (hacking / P2P / remote / cleaners / games)'
    Select-Items ($all | Where-Object { $_.DisplayName -match $BadSoftware }) { "$($_.DisplayName) $($_.DisplayVersion)" } | ForEach-Object { Uninstall-App $_ }

    if (Ask 'Uninstall something else from the full list?') {
        Select-Items $all { "$($_.DisplayName) $($_.DisplayVersion)" } | ForEach-Object { Uninstall-App $_ }
    }
    Info 'Also check Settings > Apps for Store apps, and C:\Program Files / C:\Users\*\Downloads for portable tools.'
}

function Uninstall-App($p) {
    $cmd = if ($p.QuietUninstallString) { $p.QuietUninstallString } else { $p.UninstallString }
    if ($cmd -match 'msiexec') { $cmd = ($cmd -replace '/I', '/X') + ' /qb /norestart' }
    Info "Running: $cmd  (finish any uninstaller window that opens)"
    Start-Process cmd.exe "/c `"$cmd`"" -Wait
    Ok "Ran uninstaller for $($p.DisplayName)"
}

# ==============================================================================
# 9. Prohibited files
# ==============================================================================
$MediaExt   = 'mp3', 'mp4', 'm4a', 'm4v', 'wav', 'wma', 'wmv', 'flac', 'aac', 'ogg', 'avi', 'mkv', 'mov', 'flv', 'webm', 'mpg', 'mpeg', '3gp', 'aiff'
$ImageExt   = 'jpg', 'jpeg', 'png', 'gif', 'bmp', 'heic', 'tif', 'tiff'
$SuspectExt = 'exe', 'msi', 'bat', 'cmd', 'ps1', 'vbs', 'zip', '7z', 'rar', 'iso', 'torrent', 'pcap', 'pcapng', 'kdbx'
$SuspectName = 'pass(word|wd)?s?|cred|secret|hack|crack|keygen|backdoor|payload|mimikatz|netcat|nc64|exploit|shell'

function Find-BadFiles {
    $root = Read-Host '  Folder to scan [C:\Users]'; if (-not $root) { $root = 'C:\Users' }
    $images = Ask 'Include images (jpg/png/...)?'
    Info 'Scanning...'
    $hits = Get-ChildItem $root -Recurse -File -Force -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -notmatch '\\AppData\\Local\\(Microsoft|Packages|Temp\\.+\.tmp)|\\WinSxS\\' } |
        ForEach-Object {
            $e = $_.Extension.TrimStart('.').ToLower()
            $why = if ($e -in $MediaExt) { 'media' } elseif ($images -and $e -in $ImageExt) { 'image' }
                   elseif ($_.BaseName -match $SuspectName) { 'name' } elseif ($e -in $SuspectExt) { 'type' }
            if ($why) { [pscustomobject]@{ Why = $why; File = $_ } }
        } | Sort-Object Why
    Info 'Answer forensics questions BEFORE deleting anything they might ask about.'
    Select-Items $hits { "[{0,-5}] {1}  ({2:N0} KB)" -f $_.Why, $_.File.FullName, ($_.File.Length / 1KB) } | ForEach-Object {
        Remove-Item -LiteralPath $_.File.FullName -Force -ErrorAction SilentlyContinue
        if (Test-Path -LiteralPath $_.File.FullName) { Warn "Could not delete $($_.File.FullName)" } else { Ok "Deleted $($_.File.FullName)" }
    }
}

# ==============================================================================
# 10. Review: shares, startup, tasks, backdoors, hosts, ports
# ==============================================================================
function Invoke-Review {
    Head 'Non-default SMB shares'
    Select-Items (Get-SmbShare | Where-Object { $_.Name -notmatch '^([A-Z]\$|ADMIN\$|IPC\$|print\$|NETLOGON|SYSVOL)$' }) { "$($_.Name) -> $($_.Path)" } |
        ForEach-Object { Remove-SmbShare -Name $_.Name -Force; Ok "Removed share $($_.Name)" }

    Head 'Run / RunOnce registry entries'
    $runKeys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
               'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
               'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
    $run = foreach ($k in $runKeys) {
        $p = Get-ItemProperty $k -ErrorAction SilentlyContinue
        if ($p) { $p.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object { [pscustomobject]@{ Key = $k; Name = $_.Name; Cmd = $_.Value } } }
    }
    Select-Items $run { "$($_.Name) = $($_.Cmd)" } | ForEach-Object { Remove-ItemProperty $_.Key -Name $_.Name; Ok "Removed autorun $($_.Name)" }

    Head 'Startup folders'
    Select-Items (Get-ChildItem "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\*", 'C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\*' -Force -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -ne 'desktop.ini' }) { $_.FullName } | ForEach-Object { Remove-Item $_.FullName -Force; Ok "Removed startup item $($_.FullName)" }

    Head 'Scheduled tasks outside \Microsoft\'
    Select-Items (Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft\*' }) {
        "{0}{1}  ->  {2} {3}" -f $_.TaskPath, $_.TaskName, ($_.Actions.Execute -join ';'), ($_.Actions.Arguments -join ';')
    } | ForEach-Object { Unregister-ScheduledTask -TaskName $_.TaskName -TaskPath $_.TaskPath -Confirm:$false; Ok "Deleted scheduled task $($_.TaskName)" }

    Head 'Image File Execution Options debuggers (sticky-keys style backdoors)'
    $ifeo = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options' -ErrorAction SilentlyContinue |
        ForEach-Object { $d = (Get-ItemProperty $_.PSPath).Debugger; if ($d) { [pscustomobject]@{ Path = $_.PSPath; Exe = $_.PSChildName; Debugger = $d } } }
    Select-Items $ifeo { "$($_.Exe) -> $($_.Debugger)" } | ForEach-Object { Remove-ItemProperty $_.Path -Name Debugger; Ok "Removed IFEO debugger on $($_.Exe)" }
    foreach ($exe in 'sethc', 'utilman', 'osk', 'Magnify', 'Narrator', 'DisplaySwitch') {
        $f = Get-Item "$env:windir\System32\$exe.exe" -ErrorAction SilentlyContinue
        if ($f -and $f.VersionInfo.OriginalFilename -notlike "$exe*") { Warn "$exe.exe looks replaced (is really $($f.VersionInfo.OriginalFilename)) - restore with: sfc /scannow" }
    }

    Head 'hosts file'
    $hosts = "$env:windir\System32\drivers\etc\hosts"
    $active = Get-Content $hosts | Where-Object { $_ -match '^\s*[^#\s]' }
    if (-not $active) { Say '  [=] hosts file clean' DarkGreen }
    else {
        $active | ForEach-Object { Warn "hosts: $_" }
        if (Ask 'Reset hosts file to default?') {
            (Get-Item $hosts).Attributes = 'Normal'
            Set-Content $hosts '# localhost name resolution is handled within DNS itself.' -Encoding ASCII
            ipconfig /flushdns | Out-Null; Ok 'hosts file reset'
        }
    }

    Head 'Listening TCP ports'
    Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Sort-Object LocalPort -Unique | ForEach-Object {
        Say ("  {0,-6} {1,-16} {2} (pid {3})" -f $_.LocalPort, $_.LocalAddress, (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName, $_.OwningProcess)
    }
}

# ==============================================================================
# 11. Windows features
# ==============================================================================
$BadFeatures = 'SMB1Protocol', 'SMB1Protocol-Client', 'SMB1Protocol-Server', 'TelnetClient', 'TFTP', 'SimpleTCP',
               'MicrosoftWindowsPowerShellV2Root', 'MicrosoftWindowsPowerShellV2', 'Internet-Explorer-Optional-amd64',
               'IIS-WebServerRole', 'IIS-FTPServer', 'WorkFolders-Client', 'Printing-Foundation-LPDPrintService'

function Disable-BadFeatures {
    Info 'Reading optional features (takes a moment)...'
    $on = Get-WindowsOptionalFeature -Online | Where-Object { $_.State -eq 'Enabled' -and $_.FeatureName -in $BadFeatures }
    Select-Items $on { $_.FeatureName } | ForEach-Object {
        Disable-WindowsOptionalFeature -Online -FeatureName $_.FeatureName -NoRestart -WarningAction SilentlyContinue | Out-Null
        Ok "Disabled feature $($_.FeatureName)"
    }
    Info 'Reboot to finish feature removal.'
}

# ==============================================================================
# 12. Updates
# ==============================================================================
function Update-All {
    Remove-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -Name DisableWindowsUpdateAccess -ErrorAction SilentlyContinue
    Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' NoAutoUpdate 0 'Automatic updates on'
    Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' AUOptions 4 'Auto download + schedule install'
    if ((Get-Service wuauserv).StartType -eq 'Disabled') { sc.exe config wuauserv start= demand | Out-Null }
    Start-Service wuauserv -ErrorAction SilentlyContinue
    Start-Process usoclient.exe StartInteractiveScan -ErrorAction SilentlyContinue
    Start-Process 'ms-settings:windowsupdate' -ErrorAction SilentlyContinue
    Ok 'Windows Update scan started - install everything, reboot, repeat (Server Core: sconfig option 6)'

    if (Get-Command winget -ErrorAction SilentlyContinue) {
        Head 'App updates (winget)'
        winget upgrade --include-unknown --accept-source-agreements
        Info 'Do NOT update programs you are about to uninstall.'
        $ids = Read-Host '  Package Ids to upgrade (space separated, "all", Enter = skip)'
        if ($ids -eq 'all') { winget upgrade --all --silent --accept-package-agreements --accept-source-agreements; Ok 'winget upgraded all apps' }
        elseif ($ids) { foreach ($id in $ids -split '\s+') { winget upgrade --id $id --exact --silent --accept-package-agreements --accept-source-agreements; Ok "Updated $id" } }
    } else {
        Warn 'winget not available (normal on Server). Update apps manually: Help > About / Check for updates.'
    }
    Info 'Browsers: chrome://settings/help, about:preferences (Firefox), edge://settings/help'
}

# ==============================================================================
# 13. Forensics toolkit
# ==============================================================================
function Invoke-Forensics {
    while ($true) {
        Say "`n  1 Find file by name     2 Search text in files   3 Hash file / find file by hash"
        Say   "  4 Decode string         5 Alternate data streams 6 Recently modified files"
        Say   "  7 File owner + ACL      8 SID <-> name           9 User details (net user)"
        $c = Read-Host '  Forensics (Enter = back)'
        switch ($c) {
            '' { return }
            '1' {
                $p = Read-Host '  Name pattern (e.g. *secret*)'; $r = Read-Host '  Root [C:\]'; if (-not $r) { $r = 'C:\' }
                Get-ChildItem $r -Recurse -Force -Filter $p -ErrorAction SilentlyContinue | ForEach-Object { Say "  $($_.FullName)   $($_.LastWriteTime)" }
            }
            '2' {
                $t = Read-Host '  Text to find'; $r = Read-Host '  Root [C:\Users]'; if (-not $r) { $r = 'C:\Users' }
                Get-ChildItem $r -Recurse -File -Force -ErrorAction SilentlyContinue | Where-Object { $_.Length -lt 20MB } |
                    Select-String -Pattern $t -SimpleMatch -ErrorAction SilentlyContinue |
                    ForEach-Object { Say "  $($_.Path):$($_.LineNumber)  $($_.Line.Trim())" }
            }
            '3' {
                $f = Read-Host '  File or folder'
                if (Test-Path $f -PathType Leaf) {
                    'MD5', 'SHA1', 'SHA256', 'SHA512' | ForEach-Object { Say ("  {0,-7} {1}" -f $_, (Get-FileHash $f -Algorithm $_).Hash) }
                } else {
                    $h = (Read-Host '  Hash to look for').Trim()
                    $alg = switch ($h.Length) { 32 { 'MD5' } 40 { 'SHA1' } 128 { 'SHA512' } default { 'SHA256' } }
                    Get-ChildItem $f -Recurse -File -Force -ErrorAction SilentlyContinue |
                        Where-Object { (Get-FileHash $_.FullName -Algorithm $alg -ErrorAction SilentlyContinue).Hash -eq $h } |
                        ForEach-Object { Ok "Hash match: $($_.FullName)" }
                }
            }
            '4' {
                $s = Read-Host '  Encoded string'
                try { Say "  base64 : $([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($s.Trim())))" } catch {}
                $hex = $s -replace '0x|[\s:]', ''
                if ($hex -match '^([0-9a-fA-F]{2})+$') { Say "  hex    : $(-join ($hex -split '(..)' | Where-Object { $_ } | ForEach-Object { [char][Convert]::ToByte($_, 16) }))" }
                if ($s -match '^[01\s]+$') { Say "  binary : $(-join ($s.Trim() -split '\s+' | ForEach-Object { [char][Convert]::ToByte($_, 2) }))" }
                Say "  rot13  : $(-join ($s.ToCharArray() | ForEach-Object {
                    $n = [int]$_
                    if ($n -ge 65 -and $n -le 90) { [char](($n - 52) % 26 + 65) } elseif ($n -ge 97 -and $n -le 122) { [char](($n - 84) % 26 + 97) } else { $_ } }))"
                try { Say "  url    : $([Uri]::UnescapeDataString($s))" } catch {}
            }
            '5' {
                $r = Read-Host '  Folder [C:\Users]'; if (-not $r) { $r = 'C:\Users' }
                Get-ChildItem $r -Recurse -File -Force -ErrorAction SilentlyContinue | Get-Item -Stream * -ErrorAction SilentlyContinue |
                    Where-Object { $_.Stream -notin ':$DATA', 'Zone.Identifier', 'SmartScreen' } | ForEach-Object {
                        Warn "$($_.FileName) : stream '$($_.Stream)' ($($_.Length) bytes)"
                        Say "      $((Get-Content -LiteralPath $_.FileName -Stream $_.Stream -Raw -ErrorAction SilentlyContinue) -replace '\s+', ' ' | ForEach-Object { $_.Substring(0, [Math]::Min(200, $_.Length)) })" DarkGray
                    }
            }
            '6' {
                $d = Read-Host '  Days back [3]'; if (-not $d) { $d = 3 }
                $r = Read-Host '  Root [C:\Users]'; if (-not $r) { $r = 'C:\Users' }
                Get-ChildItem $r -Recurse -File -Force -ErrorAction SilentlyContinue |
                    Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-[int]$d) -and $_.FullName -notmatch '\\AppData\\' } |
                    Sort-Object LastWriteTime -Descending | Select-Object -First 100 | ForEach-Object { Say ("  {0:yyyy-MM-dd HH:mm}  {1}" -f $_.LastWriteTime, $_.FullName) }
            }
            '7' { $f = Read-Host '  Path'; Get-Acl $f | Format-List Owner, AccessToString | Out-String | Write-Host }
            '8' {
                $x = Read-Host '  Name or SID'
                try {
                    if ($x -match '^S-1-') { Say "  $(([Security.Principal.SecurityIdentifier]$x).Translate([Security.Principal.NTAccount]).Value)" }
                    else { Say "  $((New-Object Security.Principal.NTAccount $x).Translate([Security.Principal.SecurityIdentifier]).Value)" }
                } catch { Warn 'Could not translate' }
            }
            '9' { net user (Read-Host '  Username') | Write-Host }
        }
    }
}

# ==============================================================================
# Menu
# ==============================================================================
$Menu = [ordered]@{
    '1'  = 'Users: remove/create/demote per README, passwords', { Invoke-UserAudit }
    '2'  = 'Groups: edit members (Remote Desktop Users, etc.)', { Edit-Groups }
    '3'  = 'Password + lockout policy', { Set-PasswordPolicy }
    '4'  = 'Security options (anon SAM, blank pw, UAC, SMB...)', { Set-SecurityOptions }
    '5'  = 'Firewall, Defender, audit policy', { Set-Protection }
    '6'  = 'Remote Desktop / Remote Assistance', { Set-RemoteAccess }
    '7'  = 'Services (FTP, Telnet, RemoteRegistry...)', { Set-Services }
    '8'  = 'Prohibited software', { Remove-BadSoftware }
    '9'  = 'Prohibited / media files', { Find-BadFiles }
    '10' = 'Review: shares, autoruns, tasks, backdoors, hosts, ports', { Invoke-Review }
    '11' = 'Windows features (SMBv1, Telnet, TFTP, PSv2...)', { Disable-BadFeatures }
    '12' = 'Updates (Windows + apps)', { Update-All }
    '13' = 'Forensics toolkit', { Invoke-Forensics }
    'A'  = 'Quick run: 3, 4, 5, 6', { Set-PasswordPolicy; Set-SecurityOptions; Set-Protection; Set-RemoteAccess }
}

while ($true) {
    Clear-Host
    Say ('  ' + '=' * 62) DarkCyan
    Say '   CYBERPATRIOT HARDENING TOOLKIT' White
    Say "   $($OS.Caption)  |  $env:COMPUTERNAME  |  $env:USERNAME$(if ($IsDC) { '  |  DOMAIN CONTROLLER' })" DarkGray
    Say "   Log: $Log" DarkGray
    Say ('  ' + '=' * 62) DarkCyan
    foreach ($k in $Menu.Keys) { Say ("   {0,3}  {1}" -f $k, $Menu[$k][0]) }
    Say '     Q  Quit'
    $c = (Read-Host "`n  Select").Trim().ToUpper()
    if ($c -eq 'Q') { break }
    if ($Menu.Contains($c)) {
        Say "`n  ==== $($Menu[$c][0]) ====" Magenta
        try { & $Menu[$c][1] } catch { Warn $_.Exception.Message }
        Read-Host "`n  Done. Press Enter for menu" | Out-Null
    }
}
