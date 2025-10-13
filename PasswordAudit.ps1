param(
    [Parameter(Mandatory = $false)]
    [string]$UserName,
    [int]$SinceHours = 24,
    [string]$OutputPath = ".\PasswordAudit_Report.csv",
    [switch]$UseLocalOnly,
    [switch]$UseADOnly,
    [int]$BadLogonThreshold = 3,
    [int]$PasswordAgeWarningDays = 90
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

function Audit-SingleUser {
    param(
        [Parameter(Mandatory = $true)]
        $User,
        [datetime]$Since,
        [string]$Scope,
        [int]$PasswordAgeWarning
    )
    
    $normalized = Normalize-User $User.SamAccountName
    $info = [ordered]@{}
    
    if ($Scope -eq 'AD') {
        $info.Scope = 'AD'
        $info.UserName = $User.SamAccountName
        $info.DisplayName = $User.DisplayName
        $info.Enabled = $User.Enabled
        $info.PasswordLastSet = $User.PasswordLastSet
        $info.PasswordNeverExpires = [bool]$User.PasswordNeverExpires
        $info.PasswordNotRequired = [bool]$User.PasswordNotRequired
        $info.LockedOut = [bool]$User.LockedOut
        $info.BadLogonCount = $User.BadLogonCount
        $info.LastBadPasswordAttempt = $User.LastBadPasswordAttempt
    }
    
    # Calculate password age
    $passwordAge = if ($info.PasswordLastSet) { 
        ((Get-Date) - $info.PasswordLastSet).Days 
    } else { 
        $null 
    }
    
    # Security events for this user
    $failedLogons = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4625; StartTime = $Since } -ErrorAction SilentlyContinue |
        Where-Object { Match-TargetUser $_ $normalized } |
        Measure-Object | Select-Object -ExpandProperty Count
    
    $lockouts = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4740; StartTime = $Since } -ErrorAction SilentlyContinue |
        Where-Object { $_.Message -match [regex]::Escape($normalized) } |
        Measure-Object | Select-Object -ExpandProperty Count
    
    # Identify weak policy flags
    $weakPolicy = @()
    if ($info.PasswordNeverExpires) { $weakPolicy += 'PasswordNeverExpires' }
    if ($info.PasswordNotRequired) { $weakPolicy += 'PasswordNotRequired' }
    if ($passwordAge -and $passwordAge -gt $PasswordAgeWarning) { $weakPolicy += "OldPassword($passwordAge days)" }
    if (-not $info.Enabled) { $weakPolicy += 'Disabled' }
    
    # Calculate risk score
    $riskScore = 0
    if ($info.PasswordNeverExpires) { $riskScore += 3 }
    if ($info.PasswordNotRequired) { $riskScore += 5 }
    if ($info.BadLogonCount -gt 0) { $riskScore += $info.BadLogonCount }
    if ($failedLogons -gt 0) { $riskScore += $failedLogons }
    if ($lockouts -gt 0) { $riskScore += ($lockouts * 2) }
    if ($passwordAge -and $passwordAge -gt $PasswordAgeWarning) { $riskScore += 2 }
    if (-not $info.Enabled) { $riskScore += 1 }
    
    return [pscustomobject]([ordered]@{
        UserName = $info.UserName
        DisplayName = $info.DisplayName
        Enabled = $info.Enabled
        RiskScore = $riskScore
        PasswordLastSet = $info.PasswordLastSet
        PasswordAgeDays = $passwordAge
        PasswordNeverExpires = $info.PasswordNeverExpires
        PasswordNotRequired = $info.PasswordNotRequired
        LockedOut = $info.LockedOut
        BadLogonCount = $info.BadLogonCount
        LastBadPasswordAttempt = $info.LastBadPasswordAttempt
        RecentFailedLogons = $failedLogons
        RecentLockouts = $lockouts
        WeakPolicyFlags = if ($weakPolicy.Count) { ($weakPolicy -join ', ') } else { 'None' }
    })
}

# Main execution
$since = (Get-Date).AddHours(-[math]::Abs($SinceHours))
$scope = Get-TargetScope

if ($scope -ne 'AD') {
    Write-Error "This script requires Active Directory access to audit all users. AD module not found or -UseLocalOnly specified."
    Write-Host "To audit all users, ensure the Active Directory PowerShell module is installed and you have appropriate permissions." -ForegroundColor Yellow
    return
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  Active Directory Password Audit Tool" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

Write-Host "Configuration:" -ForegroundColor Green
Write-Host "  - Audit Window: Last $SinceHours hours"
Write-Host "  - Bad Logon Threshold: $BadLogonThreshold"
Write-Host "  - Password Age Warning: $PasswordAgeWarningDays days"
Write-Host "  - Output File: $OutputPath`n"

# Get users to audit
if ($UserName) {
    Write-Host "Auditing single user: $UserName`n" -ForegroundColor Yellow
    try {
        $users = @(Get-ADUser -Identity $UserName -Properties PasswordLastSet, PasswordNeverExpires, PasswordNotRequired, LockedOut, BadLogonCount, LastBadPasswordAttempt, DisplayName, Enabled -ErrorAction Stop)
    } catch {
        Write-Error "Failed to retrieve user '$UserName': $_"
        return
    }
} else {
    Write-Host "Retrieving all Active Directory users..." -ForegroundColor Yellow
    try {
        $users = Get-ADUser -Filter * -Properties PasswordLastSet, PasswordNeverExpires, PasswordNotRequired, LockedOut, BadLogonCount, LastBadPasswordAttempt, DisplayName, Enabled
        Write-Host "Found $($users.Count) users. Starting audit...`n" -ForegroundColor Green
    } catch {
        Write-Error "Failed to retrieve AD users: $_"
        return
    }
}

# Audit all users
$results = @()
$counter = 0
$totalUsers = $users.Count

foreach ($user in $users) {
    $counter++
    $percentComplete = [math]::Round(($counter / $totalUsers) * 100, 1)
    Write-Progress -Activity "Auditing AD Users" -Status "Processing $($user.SamAccountName) ($counter of $totalUsers)" -PercentComplete $percentComplete
    
    try {
        $auditResult = Audit-SingleUser -User $user -Since $since -Scope $scope -PasswordAgeWarning $PasswordAgeWarningDays
        $results += $auditResult
    } catch {
        Write-Warning "Failed to audit user $($user.SamAccountName): $_"
    }
}

Write-Progress -Activity "Auditing AD Users" -Completed

# Export to CSV
try {
    $results | Export-Csv -Path $OutputPath -NoTypeInformation -Force
    Write-Host "`nFull report exported to: $OutputPath" -ForegroundColor Green
} catch {
    Write-Warning "Failed to export CSV: $_"
}

# Display Summary Statistics
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  AUDIT SUMMARY" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

$totalUsers = $results.Count
$enabledUsers = ($results | Where-Object { $_.Enabled }).Count
$disabledUsers = $totalUsers - $enabledUsers

Write-Host "Total Users Audited: $totalUsers" -ForegroundColor White
Write-Host "  - Enabled: $enabledUsers" -ForegroundColor Green
Write-Host "  - Disabled: $disabledUsers" -ForegroundColor Gray

Write-Host "`nPassword Policy Issues:" -ForegroundColor Yellow
$neverExpires = ($results | Where-Object { $_.PasswordNeverExpires -eq $true }).Count
$notRequired = ($results | Where-Object { $_.PasswordNotRequired -eq $true }).Count
$oldPasswords = ($results | Where-Object { $_.PasswordAgeDays -gt $PasswordAgeWarningDays }).Count
Write-Host "  - Password Never Expires: $neverExpires users" -ForegroundColor $(if($neverExpires -gt 0){"Red"}else{"Green"})
Write-Host "  - Password Not Required: $notRequired users" -ForegroundColor $(if($notRequired -gt 0){"Red"}else{"Green"})
Write-Host "  - Old Passwords (>$PasswordAgeWarningDays days): $oldPasswords users" -ForegroundColor $(if($oldPasswords -gt 0){"Yellow"}else{"Green"})

Write-Host "`nSecurity Incidents:" -ForegroundColor Yellow
$lockedOut = ($results | Where-Object { $_.LockedOut -eq $true }).Count
$highBadLogons = ($results | Where-Object { $_.BadLogonCount -ge $BadLogonThreshold }).Count
$recentFailures = ($results | Where-Object { $_.RecentFailedLogons -gt 0 }).Count
Write-Host "  - Currently Locked Out: $lockedOut users" -ForegroundColor $(if($lockedOut -gt 0){"Red"}else{"Green"})
Write-Host "  - High Bad Logon Count (>=$BadLogonThreshold): $highBadLogons users" -ForegroundColor $(if($highBadLogons -gt 0){"Red"}else{"Green"})
Write-Host "  - Recent Failed Logons: $recentFailures users" -ForegroundColor $(if($recentFailures -gt 0){"Yellow"}else{"Green"})

# Display High Risk Users
Write-Host "`n========================================" -ForegroundColor Red
Write-Host "  HIGH RISK USERS (Top 20)" -ForegroundColor Red
Write-Host "========================================`n" -ForegroundColor Red

$highRisk = $results | Where-Object { $_.RiskScore -gt 0 } | Sort-Object -Property RiskScore -Descending | Select-Object -First 20

if ($highRisk) {
    $highRisk | Format-Table -AutoSize UserName, DisplayName, RiskScore, Enabled, PasswordNeverExpires, PasswordNotRequired, BadLogonCount, RecentFailedLogons, PasswordAgeDays, WeakPolicyFlags
} else {
    Write-Host "No high-risk users identified!" -ForegroundColor Green
}

# Display Users with Weak Policies
Write-Host "`n========================================" -ForegroundColor Yellow
Write-Host "  USERS WITH PASSWORD NEVER EXPIRES" -ForegroundColor Yellow
Write-Host "========================================`n" -ForegroundColor Yellow

$neverExpiresUsers = $results | Where-Object { $_.PasswordNeverExpires -eq $true } | Select-Object -First 10
if ($neverExpiresUsers) {
    $neverExpiresUsers | Format-Table -AutoSize UserName, DisplayName, Enabled, PasswordLastSet, PasswordAgeDays
    if ($neverExpires -gt 10) {
        Write-Host "  ... and $($neverExpires - 10) more. See CSV for full list.`n" -ForegroundColor Gray
    }
} else {
    Write-Host "None found!`n" -ForegroundColor Green
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Audit completed successfully!" -ForegroundColor Green
Write-Host "Review the CSV file for complete details: $OutputPath" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan


