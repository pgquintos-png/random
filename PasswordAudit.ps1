param(
    [Parameter(Mandatory = $true)]
    [string]$UserName,
    [int]$SinceHours = 24,
    [switch]$UseLocalOnly,
    [switch]$UseADOnly
)

function Get-TargetScope {
    if ($UseADOnly) { return 'AD' }
    if ($UseLocalOnly) { return 'Local' }
    if (Get-Command Get-ADUser -ErrorAction SilentlyContinue) { return 'AD' }
    return 'Local'
}

function Normalize-User([string]$Name) {
    # Extract simple name (handles DOMAIN\user and user@domain)
    $simple = $Name.Split('\')[-1]
    if ($simple -match '@') { return $simple.Split('@')[0] }
    return $simple
}

function Match-TargetUser($Event, [string]$Normalized) {
    try {
        $xml = [xml]$Event.ToXml()
        $target = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
        if (-not $target) { return $false }
        return ($target -ieq $Normalized)
    } catch {
        return $false
    }
}

$since = (Get-Date).AddHours(-[math]::Abs($SinceHours))
$scope = Get-TargetScope
$normalized = Normalize-User $UserName

$info = [ordered]@{}

if ($scope -eq 'AD') {
    try {
        $adUser = Get-ADUser -Identity $UserName -Properties PasswordLastSet, PasswordNeverExpires, PasswordNotRequired, LockedOut, BadLogonCount, LastBadPasswordAttempt
        $info.Scope = 'AD'
        $info.UserName = $adUser.SamAccountName
        $info.PasswordLastSet = $adUser.PasswordLastSet
        $info.PasswordNeverExpires = [bool]$adUser.PasswordNeverExpires
        $info.PasswordNotRequired = [bool]$adUser.PasswordNotRequired
        $info.LockedOut = [bool]$adUser.LockedOut
        $info.BadLogonCount = $adUser.BadLogonCount
        $info.LastBadPasswordAttempt = $adUser.LastBadPasswordAttempt
    } catch {
        Write-Verbose "AD lookup failed for '$UserName' ($_). Falling back to Local."
        $scope = 'Local'
    }
}

if ($scope -eq 'Local') {
    try {
        $local = Get-LocalUser -Name $normalized -ErrorAction Stop
        $info.Scope = 'Local'
        $info.UserName = $local.Name
        $info.PasswordLastSet = $local.PasswordLastSet
        $info.PasswordExpires = $local.PasswordExpires
        $info.PasswordChangeable = $local.UserMayChangePassword
        $info.PasswordRequired = $local.PasswordRequired
        $info.Enabled = $local.Enabled
    } catch {
        Write-Error "User '$UserName' not found as local user and AD lookup not available/failed."
        return
    }
}

# Security events
$pwdChangeEvents = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4723, 4724; StartTime = $since } -ErrorAction SilentlyContinue |
    Where-Object { Match-TargetUser $_ $normalized } |
    Select-Object TimeCreated, Id, ProviderName, Message |
    Sort-Object TimeCreated

$failedLogons = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4625; StartTime = $since } -ErrorAction SilentlyContinue |
    Where-Object { Match-TargetUser $_ $normalized } |
    Select-Object TimeCreated, Id, ProviderName, Message |
    Sort-Object TimeCreated

$lockouts = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4740; StartTime = $since } -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match [regex]::Escape($normalized) } |
    Select-Object TimeCreated, Id, Message |
    Sort-Object TimeCreated

# Weak policy flags (cannot validate actual password strength)
$weakPolicy = @()
if ($info.Contains('PasswordNeverExpires') -and $info.PasswordNeverExpires) { $weakPolicy += 'PasswordNeverExpires' }
if ($info.Contains('PasswordNotRequired') -and $info.PasswordNotRequired) { $weakPolicy += 'PasswordNotRequired' }
if ($info.Contains('PasswordRequired') -and -not $info.PasswordRequired) { $weakPolicy += 'PasswordNotRequired' }
if ($info.Contains('PasswordExpires') -and -not $info.PasswordExpires) { $weakPolicy += 'PasswordNeverExpires' }

$report = [pscustomobject]([ordered]@{
    UserName = $info.UserName
    Scope = $info.Scope
    PasswordLastSet = $info.PasswordLastSet
    PasswordNeverExpires = $info.PasswordNeverExpires
    PasswordNotRequired = $info.PasswordNotRequired
    LockedOut = $info.LockedOut
    BadLogonCount = $info.BadLogonCount
    LastBadPasswordAttempt = $info.LastBadPasswordAttempt
    FailedLogonsCount = ($failedLogons | Measure-Object).Count
    LastFailedLogon = if ($failedLogons) { $failedLogons[-1].TimeCreated } else { $null }
    PasswordChangeEventsCount = ($pwdChangeEvents | Measure-Object).Count
    LastPasswordChangeEvent = if ($pwdChangeEvents) { $pwdChangeEvents[-1].TimeCreated } else { $null }
    LockoutsCount = ($lockouts | Measure-Object).Count
    LastLockout = if ($lockouts) { $lockouts[-1].TimeCreated } else { $null }
    WeakPolicyFlags = if ($weakPolicy.Count) { ($weakPolicy -join ',') } else { '' }
})

$report

Write-Host "" 
Write-Host ("Recent Password Change Events (since {0})" -f $since) -ForegroundColor Cyan
$pwdChangeEvents | Format-Table -AutoSize TimeCreated, Id

Write-Host "" 
Write-Host ("Recent Failed Logons (since {0})" -f $since) -ForegroundColor Yellow
$failedLogons | Format-Table -AutoSize TimeCreated, Id

Write-Host "" 
Write-Host ("Recent Lockouts (since {0})" -f $since) -ForegroundColor Red
$lockouts | Format-Table -AutoSize TimeCreated, Id

Write-Host "" 
if (-not ($pwdChangeEvents -or $failedLogons -or $lockouts)) {
    Write-Host "No related Security log events found in the window. If expected, run PowerShell as Administrator and ensure auditing is enabled." -ForegroundColor DarkGray
}


