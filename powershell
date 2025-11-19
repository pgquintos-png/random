$user = Read-Host "Enter username"
Get-ADUser -Identity $user -Properties MemberOf | Select-Object -ExpandProperty MemberOf | 
    ForEach-Object { ($_ -split ',')[0] -replace 'CN=' } | 
    ForEach-Object { Write-Host $_ }
