param(
    [string]$UserName,
    [string]$OutputPath = ".\PasswordAudit.csv",
    [int]$PasswordAgeWarning = 90
)

# Check AD module
if (-not (Get-Command Get-ADUser -ErrorAction SilentlyContinue)) {
    Write-Error "Active Directory module not found. Install RSAT tools."
    return
}

Write-Host "Starting AD Password Audit..." -ForegroundColor Cyan

# Get users
$properties = 'PasswordLastSet','PasswordNeverExpires','PasswordNotRequired','LockedOut','BadLogonCount','DisplayName','Enabled'
if ($UserName) {
    $users = Get-ADUser -Identity $UserName -Properties $properties
} else {
    $users = Get-ADUser -Filter "Enabled -eq `$true" -Properties $properties
}

Write-Host "Auditing $($users.Count) user(s)..." -ForegroundColor Yellow

# Audit users
$results = foreach ($user in $users) {
    $passwordAge = if ($user.PasswordLastSet) { ((Get-Date) - $user.PasswordLastSet).Days } else { $null }
    
    # Calculate risk score
    $risk = 0
    if ($user.PasswordNeverExpires) { $risk += 3 }
    if ($user.PasswordNotRequired) { $risk += 5 }
    if ($user.BadLogonCount -gt 0) { $risk += $user.BadLogonCount }
    if ($passwordAge -gt $PasswordAgeWarning) { $risk += 2 }
    
    [PSCustomObject]@{
        UserName = $user.SamAccountName
        DisplayName = $user.DisplayName
        Enabled = $user.Enabled
        RiskScore = $risk
        PasswordLastSet = $user.PasswordLastSet
        PasswordAgeDays = $passwordAge
        PasswordNeverExpires = $user.PasswordNeverExpires
        PasswordNotRequired = $user.PasswordNotRequired
        LockedOut = $user.LockedOut
        BadLogonCount = $user.BadLogonCount
    }
}

# Export results
$results | Export-Csv -Path $OutputPath -NoTypeInformation
Write-Host "`nExported to: $OutputPath" -ForegroundColor Green

# Summary
Write-Host "`n=== SUMMARY ===" -ForegroundColor Cyan
Write-Host "Total Users: $($results.Count)"
Write-Host "Password Never Expires: $(($results | Where-Object PasswordNeverExpires).Count)" -ForegroundColor Yellow
Write-Host "Password Not Required: $(($results | Where-Object PasswordNotRequired).Count)" -ForegroundColor Yellow
Write-Host "Old Passwords (>$PasswordAgeWarning days): $(($results | Where-Object {$_.PasswordAgeDays -gt $PasswordAgeWarning}).Count)" -ForegroundColor Yellow
Write-Host "Locked Out: $(($results | Where-Object LockedOut).Count)" -ForegroundColor Red

# Show top 10 high risk users
$highRisk = $results | Where-Object {$_.RiskScore -gt 0} | Sort-Object RiskScore -Descending | Select-Object -First 10
if ($highRisk) {
    Write-Host "`n=== HIGH RISK USERS ===" -ForegroundColor Red
    $highRisk | Format-Table UserName, RiskScore, PasswordNeverExpires, PasswordAgeDays, BadLogonCount -AutoSize
}

Write-Host "`nAudit complete!" -ForegroundColor Green
