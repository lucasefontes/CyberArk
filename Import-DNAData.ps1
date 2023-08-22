[CmdletBinding()]
[OutputType()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SpreadSheetPath,
    
        [Parameter(Mandatory = $true)]
        [string]$ReportPath
    )
Clear-Host
$SpreadSheetPath = $SpreadSheetPath.Replace('"',"")
$ReportPath = $ReportPath.Replace('"',"")
$SpreadSheetPath = $script:SpreadSheetPath
$ReportPath = $script:ReportPath
    
$MachineName = "Machine Name"
$MachineType = "Machine Type"
$AccountName = "Account Name"
$AccountDisplayName = "Account Display Name"
$AccountType = "Account Type"  
$AccountCategory = "Account Category"
$AccountGroup = "Account Group"
$PrivilegedDomainGroup = "Privileged Domain Group"
$PassTheHashVulnerable = "Pass-the-Hash: Vulnerable"
$PassTheHashHashFound = "Pass-the-Hash: Hash Found"
$AccountDescription = "Account Description"
$ComplianceStatus = "Compliance Status"
$AccountState = "Account State"
$PasswordNeverExpires = "Password Never Expires"
$PasswordAge = "Password Age"
$ServiceAccountType = "Service Account Type"
$HardCodedFile = "Hard-Coded in File"
$HardCodedCredential = "Hard-Coded Credential"
$ApplicationServer = "Application Server"
$ApplicationName = "Application Name"
$HashTableAccountName = @{Name="$AccountName";expression={$_.$AccountName};Alignment="Center"}
$HashTableMachineType = @{Name="$MachineType";expression={$_.$MachineType};Alignment="Center"}
$HashTableAccountType = @{Name="$AccountType";expression={$_.$AccountType};Alignment="Center"}
$HashTableMachineName = @{Name="$MachineName";expression={$_.$MachineName};Alignment="Center"}
$HashTableAccountState = @{Name="$AccountState";expression={$_.$AccountState};Alignment="Center"}
$HashTableAccountGroup = @{Name="$AccountGroup";expression={$_.$AccountGroup};Alignment="Center"}
$HashTableAccountCategory = @{Name="$AccountCategory";Expression={$_.$AccountCategory};Alignment="Center"}
$HashTablePasswordAge = @{Name="$PasswordAge";expression={[int]$_.$PasswordAge};Alignment="Center"}
$HashTablePasswordNeverExpires = @{Name="$PasswordNeverExpires";Expression={$_.$PasswordNeverExpires};Alignment="Center"}
$HashTableAccountDescription = @{Name="$AccountDescription";Expression={$_.$AccountDescription};Alignment="Center"} 
$HashTablePrivilegeDomainGroup = @{Name="$PrivilegedDomainGroup";Expression={$_.$PrivilegedDomainGroup};Alignment="Center"}
$HashTableComplianceStatus = @{Name="$ComplianceStatus";Expression={$_.$ComplianceStatus};Alignment="Center"}
$HashTableAccountDisplayName = @{Name="$AccountDisplayName";Expression={$_.$AccountDisplayName};Alignment="Center"}
$HashTablePassTheHashHashFound = @{Name="$PassTheHashHashFound";Expression={$_.$PassTheHashHashFound};Alignment="Center"}
$HashTableServiceAccountType = @{Name="$ServiceAccountType";Expression={$_.$ServiceAccountType};Alignment="Center"}
$HashTableHardCodedFile = @{Name="$HardCodedFile";Expression={$_.$HardCodedFile};Alignment="Center"}
$HashTableHardCodedCredential = @{Name="$HardCodedCredential";Expression={$_.$HardCodedCredential};Alignment="Center"}

    if (-not (Test-Path $SpreadSheetPath)){
        throw "Path $SpreadSheetPath does not exist"
    }

    if (-not (Test-Path $ReportPath)){
        throw "Path $ReportPath does not exist"
    }

    Function Get-DNAData {
        param(
        [Parameter(Mandatory = $true)]
        [string]$SpreadSheetPath,
    
        [Parameter(Mandatory = $true)]
        [string]$ReportPath
        )

        $script:WindowsScanSheetInfo_Params = @{
            "WorkSheetName" = "Windows Scan"
            "StartRow" = 2
            "EndRow" = 8
            "StartColumn" = 3 
            "EndColumn" = 4
        }

        $script:WindowsScanSheetData_Params = @{
            "WorkSheetName" = "Windows Scan"
            "StartRow" = 11
        }

        Write-Host ("Getting Scan Info, please wait.")

        $script:ScanInfo = Import-Excel -Path $SpreadSheetPath @WindowsScanSheetInfo_Params
        Start-Sleep -Seconds 3

        Write-Host ("Getting data from Windows Scan Sheet, please wait.")

        $script:WindowsSheetData = Import-Excel -Path $SpreadSheetPath @WindowsScanSheetData_Params    
        
        $HardCodedSheet_Params = @{
            "WorkSheetName" = "Hard-Coded Credentials"
            "StartRow" = 2
        }

        Write-Output ("Getting data from Hard-Coded Credentials sheet, please wait.")
        $script:HardCodedData = Import-Excel -Path $SpreadSheetPath @HardCodedSheet_Params 
        

        Write-Host ("Data colllected successfully, displaying in the console in few seconds...")
        Start-Sleep -Seconds 5
        Clear-Host

        $ScanInfoReport = Join-Path $ReportPath "ScanInformation.txt"
        $ScanInfo | Tee-Object -FilePath $ScanInfoReport | Out-Null
        $ScanInfo | Out-Host
        
    }

    $TranscriptLocation = Join-Path "$ReportPath" "SUMMARY_SAME_OUTPUT_FROM_CONSOLE.txt"
    Start-Transcript -Path $TranscriptLocation -UseMinimalHeader

    Get-DNAData -SpreadSheetPath $SpreadSheetPath -ReportPath $ReportPath

    Function Get-UniqueMachine {
        param(
            [Parameter(Mandatory = $true)]
            [string]$ReportPath
            )

            $UniqueTotalMachines = Join-Path "$ReportPath" "UniqueTotalMachines.txt"

            $NumberOfMachinesVar = $WindowsSheetData | Sort-Object -Property $MachineName -Unique

            $NumberOfMachines = $NumberOfMachinesVar.Count
            Write-Host ("Total number of Machines: $NumberOfMachines")

            $NumberOfMachinesVar | Format-Table -Property `
            $HashTableMachineName,$HashTableMachineType
            | Tee-Object -FilePath $UniqueTotalMachines | Out-Null
    }

    Get-UniqueMachine -ReportPath $ReportPath

    Function Get-Server{
        param(
            [Parameter(Mandatory = $true)]
            [string]$ReportPath
            )

            $ReportNumberOfServers = Join-Path "$ReportPath" "NumberOfServers.txt"

            $NumberOfServers = $WindowsSheetData | Sort-Object -Property $MachineName -Unique | 
            Where-Object {$_.$MachineType -like "Server*"}

            $NumberOfWServersVar = $NumberOfServers.Count
            Write-Host ("Total number of Servers: $NumberOfWServersVar")

            $NumberOfServers | Format-Table -Property `
            $HashTableMachineName,$HashTableMachineType |
            Tee-Object $ReportNumberOfServers | Out-Null
    }

    Get-Server -ReportPath $ReportPath

    Function Get-Workstation {
        param(
            [Parameter(Mandatory = $true)]
            [string]$ReportPath
            )

            $ReportNumberOfWorkstations = Join-Path "$ReportPath" "NumberOfWorkstations.txt"

            $NumberOfWorkstation = $WindowsSheetData | Sort-Object -Property $MachineName -Unique |
            Where-Object {$_.$MachineType -like "Workstation*"}

            $NumberOfWorkstationVar = $NumberOfWorkstation.Count
            Write-Host ("Total number of Workstations: $NumberOfWorkstationVar")

            $NumberOfWorkstation | Format-Table -Property `
            $HashTableMachineName,$HashTableMachineType |
            Tee-Object $ReportNumberOfWorkstations | Out-Null
    }

    Get-Workstation -ReportPath $ReportPath

   Write-Host ("
Local Accounts Summary:
-----------------------") -ForegroundColor Green
   
    Function Get-UniqueLocalAccount{
        param(
        [Parameter(Mandatory = $true)]
        [string]$ReportPath
        )

            $script:UniqueLocalAccounts = Join-Path "$ReportPath" "UniqueLocalAccounts.txt"

            $script:NumberOfLocalAccountsVar = $WindowsSheetData |
                Where-Object {$_.$MachineName -notlike "*Group*" -and $_.$AccountType -like "Local*"}

            $script:NumberOfLocalAccounts = $NumberOfLocalAccountsVar.Count
            Write-Host ("Unique Accounts: $NumberOfLocalAccounts")

            $NumberOfLocalAccountsVar | Sort-Object -Property $PasswordAge -Descending | Format-Table -Property `
            $HashTableAccountName,$HashTableAccountType,$HashTablePasswordAge,$HashTableMachineName, `
            $HashTableAccountState,$HashTableAccountCategory |
            Tee-Object $UniqueLocalAccounts | Format-Table | Out-Null
    }
 
    Get-UniqueLocalAccount -ReportPath $ReportPath

    Function Get-DisabledLocalAccount {
        param(
            [Parameter(Mandatory = $true)]
            [string]$ReportPath
            )

            $DisabledLocalAccounts = Join-Path "$ReportPath" "DisabledLocalAccounts.txt"

            $NumberOfDisabledAccountsVar = $WindowsSheetData |
            Where-Object {$_.$AccountState -like "Disabled*" -and $_.$AccountName -notlike "*Group*" `
            -and $_.$AccountType -like "Local*"}

            $NumberOfDisabledAccounts = $NumberOfDisabledAccountsVar.Count
            $PercentageDisabledLocalAccounts = [math]::round(($NumberOfDisabledAccounts / $NumberOfLocalAccounts) * 100,2)
            Write-Host ("Disabled: $NumberOfDisabledAccounts | $PercentageDisabledLocalAccounts%")

            $NumberOfDisabledAccountsVar | Sort-Object -Property $PasswordAge -Descending | Format-Table -Property `
            $HashTableAccountName,$HashTableAccountState,$HashTablePasswordAge,$HashTableAccountType, `
            $HashTableAccountCategory,$HashTableMachineName |
            Tee-Object -FilePath $DisabledLocalAccounts | Out-Null
    }

    Get-DisabledLocalAccount -ReportPath $ReportPath

    Function Get-CompliantLocalAccount{
        param(
            [Parameter(Mandatory = $true)]
            [string]$ReportPath
            )

            $CompliantLocalAccountsReport = Join-Path "$ReportPath" "CompliantLocalAccounts.txt"

            $NumberOfCompliantLocalAccountsVar = $WindowsSheetData |
            Where-Object {$_.$ComplianceStatus -like "Compliant*" -and $_.$AccountName -notlike "*Group*" `
            -and $_.$AccountType -like "Local*"} 

            $NumberOfCompliantLocalAccounts = $NumberOfCompliantLocalAccountsVar.Count
            $PercentageCompliantLocalAccounts = [math]::round(($NumberOfCompliantLocalAccounts / $NumberOfLocalAccounts) * 100,2)

            Write-Host ("Compliant: $NumberOfCompliantLocalAccounts | $PercentageCompliantLocalAccounts%")

            $NumberOfCompliantLocalAccountsVar | Sort-Object -Property $PasswordAge -Descending | Format-Table -Property `
            $HashTableAccountName,$HashTableComplianceStatus,$HashTablePasswordAge, `
            $HashTableAccountState,$HashTableAccountCategory,$HashTableAccountType,$HashTableMachineName | 
            Tee-Object -FilePath $CompliantLocalAccountsReport | Out-Null
    }

    Get-CompliantLocalAccount -ReportPath $ReportPath

    Function Get-NonCompliantLocalAccount{
        param(
            [Parameter(Mandatory = $true)]
            [string]$ReportPath
            )

            $NonCompliantLocalAccountsReport = Join-Path "$ReportPath" "NonCompliantLocalAccounts.txt"

            $NumberOfNonCompliantLocalAccountsVar = $WindowsSheetData |
            Where-Object {$_.$ComplianceStatus -like "Non-compliant*" -and $_.$AccountName -notlike "*Group*" `
            -and $_.$AccountType -like "Local*"} 

            $NumberOfNonCompliantLocalAccounts = $NumberOfNonCompliantLocalAccountsVar.Count
            $PercentageNonCompliant = [math]::round(($NumberOfNonCompliantLocalAccounts / $NumberOfLocalAccounts) * 100,2)
            Write-Host ("Non-Compliant: $NumberOfNonCompliantLocalAccounts | $PercentageNonCompliant%")

            $NumberOfNonCompliantLocalAccountsVar | Sort-Object -Property $PasswordAge -Descending | Format-Table -Property `
            $HashTableAccountName,$HashTablePasswordAge,$HashTableAccountState, `
            $HashTableAccountCategory,$HashTableAccountType,$HashTableMachineName,$HashTableComplianceStatus | 
            Tee-Object -FilePath $NonCompliantLocalAccountsReport | Out-Null
    }

    Get-NonCompliantLocalAccount -ReportPath $ReportPath

    Function Get-LockedLocalAccount {
        param(
            [Parameter(Mandatory = $true)]
            [string]$ReportPath
            )

            $ReportLockedLocalAccounts = Join-Path "$ReportPath" "LockedLocalAccounts.txt"

            $NumberOfLockedLocalAccountsVar = $WindowsSheetData |
            Where-Object {$_.$AccountState -like "Locked*" -and $_.$AccountName -notlike "*Group*" -and $_.$AccountType -notlike "Domain*"}
            
            $NumberOfLockedLocalAccounts = $NumberOfLockedLocalAccountsVar.Count
            $PercentageLocal = [math]::round(($NumberOfLockedLocalAccounts / $NumberOfLocalAccounts) * 100,2)
            Write-Host ("Locked: $NumberOfLockedLocalAccounts | $PercentageLocal%")
            
            $NumberOfLockedLocalAccountsVar | Sort-Object -Property $PasswordAge -Descending | Format-Table -Property `
            $HashTableAccountName,$HashTableAccountState,$HashTablePasswordAge,$HashTableAccountType |
            Tee-Object -FilePath $ReportLockedLocalAccounts | Out-Null

    }

    Get-LockedLocalAccount -ReportPath $ReportPath

    Function Get-PrivilegedLocalAccount{
        param(
            [Parameter(Mandatory = $true)]
            [string]$ReportPath
            )

            $ReportPrivilegeLocalAccounts = Join-Path "$ReportPath" "PrivilegeLocalAccounts.txt"

            $PrivilegeLocalAccounts = $WindowsSheetData |
            Where-Object {$_.$AccountCategory -like "Privilege*" -and $_.$AccountName -notlike "*Group*" `
            -and $_.$AccountType -like "Local*" -and $_.$AccountState -like "Enabled*"}

            $PrivilegeLocalAccountsVar = $PrivilegeLocalAccounts.Count
            Write-Host ("Privileged: $PrivilegeLocalAccountsVar")

            $PrivilegeLocalAccounts | Sort-Object -Property $PasswordAge -Descending | Format-Table -Property `
            $HashTableAccountName,$HashTableAccountGroup,$HashTablePasswordAge,
            $HashTableAccountCategory,$HashTableMachineName,$HashTableAccountState,$HashTableAccountType|
            Tee-Object -FilePath $ReportPrivilegeLocalAccounts | Out-Null
    }

    Get-PrivilegedLocalAccount -ReportPath $ReportPath

    Function Get-LocalServiceAccount {
        param(
            [Parameter(Mandatory = $true)]
            [string]$ReportPath
            )

            $ReportLocalServiceAccounts = Join-Path "$ReportPath" "LocalServiceAccounts.txt"

            $LocalServiceAccountsVar = $WindowsSheetData |
            Where-Object {$_.$AccountState -like "Enabled*" -and $_.$AccountCategory -like "Service Account*" `
            -and $_.$AccountType -like "Local*"}

            $LocalServiceAccounts = $LocalServiceAccountsVar.Count
            Write-Host ("Service Accounts: $LocalServiceAccounts")

            $LocalServiceAccountsVar | Sort-Object -Property $PasswordAge -Descending | Format-Table -Property `
            $HashTableAccountName,$HashTableAccountType,$HashTablePasswordAge,$HashTableAccountCategory,$HashTableServiceAccountType,
            $HashTableMachineName |
            Tee-Object -FilePath $ReportLocalServiceAccounts | Out-Null
    }

    Get-LocalServiceAccount -ReportPath $ReportPath

    Write-Host ("
Domain Accounts Summary:
------------------------") -ForegroundColor Green

    Function Get-UniqueDomainAccount{
        param(
        [Parameter(Mandatory = $true)]
        [string]$ReportPath
        )

            $script:UniqueDomainAccounts = Join-Path "$ReportPath" "UniqueDomainAccounts.txt"

            $script:NumberOfDomainAccountsVar = $WindowsSheetData | Where-Object {$_.$AccountName -notlike "*Group*" `
            -and $_.$AccountType -like "Domain*"} |
            Sort-Object -Property $AccountName -Unique

            $script:NumberOfDomainAccounts = $NumberOfDomainAccountsVar.Count
            Write-Host("Unique Accounts: $NumberOfDomainAccounts")

            $NumberOfDomainAccountsVar | Sort-Object -Property $PasswordAge -Descending | Format-Table -Property `
            $HashTableAccountName,$HashTableAccountType,$HashTablePasswordAge,$HashTableAccountState,$HashTableAccountCategory | 
            Tee-Object -FilePath $UniqueDomainAccounts | Out-Null
    }

    Get-UniqueDomainAccount -ReportPath $ReportPath

    Function Get-DisabledDomainAccount{
        param(
            [Parameter(Mandatory = $true)]
            [string]$ReportPath
            )

            $DisabledDomainAccounts = Join-Path "$ReportPath" "DisabledDomainAccounts.txt"

            $NumberOfDisabledAccountsVar = $WindowsSheetData | Sort-Object -Property $AccountName -Unique |
            Where-Object {$_.$AccountState -like "Disabled*" -and $_.$AccountName -notlike "*Group*" `
            -and $_.$AccountType -like "*Domain*"} 

            $NumberOfDisabledAccounts = $NumberOfDisabledAccountsVar.Count
            $PercentageDisabledDomainAccounts = [math]::round(($NumberOfDisabledAccounts / $NumberOfDomainAccounts) * 100,2)
            Write-Host ("Disabled: $NumberOfDisabledAccounts | $PercentageDisabledDomainAccounts%")

            $NumberOfDisabledAccountsVar | Sort-Object -Property $PasswordAge -Descending | Format-Table -Property `
            $HashTableAccountName,$HashTableAccountState,$HashTablePasswordAge,$HashTableAccountCategory,$HashTableAccountType | 
            Tee-Object -FilePath $DisabledDomainAccounts | Out-Null
    }

    Get-DisabledDomainAccount -ReportPath $ReportPath

    Function Get-CompliantDomainAccount{
        param(
            [Parameter(Mandatory = $true)]
            [string]$ReportPath
            )

            $CompliantDomainAccountsReport = Join-Path "$ReportPath" "CompliantDomainAccounts.txt"

            $NumberOfCompliantDomainAccountsVar = $WindowsSheetData | Sort-Object -Property $AccountName -Unique |
            Where-Object {$_.$ComplianceStatus -like "Compliant*" -and $_.$AccountName -notlike "*Group*" `
            -and $_.$AccountType -like "Domain*"} 

            $NumberOfCompliantDomainAccounts = $NumberOfCompliantDomainAccountsVar.Count
            $PercentageCompliantDomainAccounts = [math]::round(($NumberOfCompliantDomainAccounts / $NumberOfDomainAccounts) * 100,2)
            Write-Host ("Compliant: $NumberOfCompliantDomainAccounts | $PercentageCompliantDomainAccounts%")

            $NumberOfCompliantDomainAccountsVar | Sort-Object -Property $PasswordAge -Descending | Format-Table -Property `
            $HashTableAccountName,$HashTableComplianceStatus,$HashTablePasswordAge, `
            $HashTableAccountState,$HashTableAccountType,$HashTableAccountCategory | 
            Tee-Object -FilePath $CompliantDomainAccountsReport | Out-Null
    }

    Get-CompliantDomainAccount -ReportPath $ReportPath

    Function Get-NonCompliantDomainAccount{
        param(
            [Parameter(Mandatory = $true)]
            [string]$ReportPath
            )

            $NonCompliantDomainAccountsReport = Join-Path "$ReportPath" "NonCompliantDomainAccounts.txt"

            $NumberOfNonCompliantDomainAccountsVar = $WindowsSheetData | Sort-Object -Property $AccountName -Unique |
            Where-Object {$_.$ComplianceStatus -like "Non-compliant*" -and $_.$AccountName -notlike "*Group*" `
            -and $_.$AccountType -like "Domain*"} 

            $NumberOfNonCompliantDomainAccounts = $NumberOfNonCompliantDomainAccountsVar.Count
            $PercentageNonCompliantDomainAccounts = [math]::round(($NumberOfNonCompliantDomainAccounts / $NumberofDomainAccounts) * 100,2)
            Write-Host ("Non-Compliant: $NumberOfNonCompliantDomainAccounts | $PercentageNonCompliantDomainAccounts%")

            $NumberOfNonCompliantDomainAccountsVar | Sort-Object -Property $PasswordAge -Descending | Format-Table -Property `
            $HashTableAccountName,$HashTablePasswordAge,$HashTableAccountState,$HashTableAccountCategory, `
            $HashTableAccountType,$HashTableComplianceStatus | 
            Tee-Object -FilePath $NonCompliantDomainAccountsReport | Out-Null
    }

    Get-NonCompliantDomainAccount -ReportPath $ReportPath


    Function Get-ExpiredAccount {
        param(
            [Parameter(Mandatory = $true)]
            [string]$ReportPath
            )

            $ExpiredAccounts = Join-Path "$ReportPath" "ExpiredAccounts.txt"

            $NumberOfExpiredAccountsVar = $WindowsSheetData |
            Where-Object {$_.$AccountState -like "Expired*" -and $_.$AccountName -notlike "*Group*"}

            $NumberOfExpiredAccounts = $NumberOfExpiredAccountsVar.Count
            $PercentageExpiredAccounts = [math]::round(($NumberOfExpiredAccounts / $NumberofDomainAccounts) * 100,2)
            Write-Host ("Expired: $NumberOfExpiredAccounts | $PercentageExpiredAccounts%")

            $NumberOfExpiredAccountsVar | Sort-Object -Property $PasswordAge -Descending | Format-Table -Property `
            $HashTableAccountName,$HashTableAccountState,$HashTablePasswordAge,$HashTableAccountType,$HashTableMachineName |
            Tee-Object -FilePath $ExpiredAccounts | Out-Null

    }

    Get-ExpiredAccount -ReportPath $ReportPath

    Function Get-LockedDomainAccount {
        param(
            [Parameter(Mandatory = $true)]
            [string]$ReportPath
            )

            $ReportLockedDomainAccounts = Join-Path "$ReportPath" "LockedDomainAccounts.txt"

            $NumberOfLockedDomainAccountsVar = $WindowsSheetData | Sort-Object -Property $AccountName -Unique |
            Where-Object {$_.$AccountState -like "Locked*" -and $_.$AccountName -notlike "*Group*" -and $_.$AccountType -like "Domain*"}
            
            $NumberOfLockedDomainAccounts = $NumberOfLockedDomainAccountsVar.Count
            $PercentageLockedDomain= [math]::round(($NumberOfLockedDomainAccounts / $NumberofDomainAccounts) * 100,2)
            Write-Host ("Locked: $NumberOfLockedDomainAccounts | $PercentageLockedDomain%")
            
            $NumberOfLockedDomainAccountsVar | Sort-Object -Property $PasswordAge -Descending | Format-Table -Property `
            $HashTableAccountName,$HashTableAccountState,$HashTablePasswordAge,$HashTableAccountType |
            Tee-Object -FilePath $ReportLockedDomainAccounts | Out-Null

    }

    Get-LockedDomainAccount -ReportPath $ReportPath

    Function Get-PrivilegedDomainAccount{
        param(
            [Parameter(Mandatory = $true)]
            [string]$ReportPath
            )

            $ReportPrivilegeDomainAccounts = Join-Path "$ReportPath" "PrivilegeDomainAccounts.txt"

            $PrivilegeDomainAccounts = $WindowsSheetData | Sort-Object -Property $AccountName -Unique |
            Where-Object {$_.$AccountCategory -like "Privilege*" -and $_.$AccountName -notlike "*Group*" `
            -and $_.$AccountType -notlike "Local*" -and $_.$AccountState -like "Enabled*"}

            $PrivilegeDomainAccountsVar = $PrivilegeDomainAccounts.Count
            Write-Host ("Privileged: $PrivilegeDomainAccountsVar")

            $PrivilegeDomainAccounts | Sort-Object -Property $PasswordAge -Descending |Format-Table -Property `
            $HashTableAccountName,$HashTableAccountGroup,$HashTablePrivilegeDomainGroup,$HashTablePasswordAge,
            $HashTableAccountCategory,$HashTableAccountState,$HashTableAccountType|
            Tee-Object -FilePath $ReportPrivilegeDomainAccounts | Out-Null
    }

    Get-PrivilegedDomainAccount -ReportPath $ReportPath

    Function Get-DomainServiceAccount {
        param(
            [Parameter(Mandatory = $true)]
            [string]$ReportPath
            )

            $ReportDomainServiceAccounts = Join-Path "$ReportPath" "DomainServiceAccounts.txt"

            $DomainServiceAccountsVar = $WindowsSheetData | Sort-Object -Property $AccountName -Unique |
            Where-Object {$_.$AccountState -like "Enabled*" -and $_.$AccountCategory -like "Service Account*" `
            -and $_.$AccountType -like "Domain*"}

            $DomainServiceAccounts = $DomainServiceAccountsVar.Count
            Write-Host ("Service Accounts: $DomainServiceAccounts")

            $DomainServiceAccountsVar | Sort-Object -Property $PasswordAge -Descending | Format-Table -Property `
            $HashTableAccountName,$HashTableAccountType,$HashTablePasswordAge,$HashTableAccountCategory,$HashTableServiceAccountType |
            Tee-Object -FilePath $ReportDomainServiceAccounts | Out-Null
    }

    Get-DomainServiceAccount -ReportPath $ReportPath
    
    Function Get-DomainAdmin {
            param(
                [Parameter(Mandatory = $true)]
                [string]$ReportPath
                )

            $ReportLocationDomainAdminAccounts = Join-Path "$ReportPath" "DomainAdminAccounts.txt"

Write-Host ("
Domain Admins:
-------------") -ForegroundColor Green

            $DomainAdmins = $WindowsSheetData | Sort-Object -Property $AccountName -Unique | 
            Where-Object {$_.$PrivilegedDomainGroup -like "Domain Admins*" -and $_.$AccountName -notlike "*Group*"}

            $DomainAdmins | Sort-Object -Property $PasswordAge -Descending | Format-Table -Property `
            $HashTableAccountName,$HashTablePrivilegeDomainGroup,$HashTableAccountDisplayName,$HashTableAccountState,
            $HashTablePasswordAge |
            Tee-Object -FilePath $ReportLocationDomainAdminAccounts
    }

    Get-DomainAdmin -ReportPath $ReportPath

    Function Get-WideSpreadAccess {
            param(
                [Parameter(Mandatory = $true)]
                [string]$ReportPath
                )

            $ReportWideSpreadAccess = Join-Path "$ReportPath" "WideSpreadAccessServers.txt"

            $WideSpreadAccess =  $WindowsSheetData | Where-Object {$_.$AccountGroup -like "Administrators*" `
            -and $_.$AccountType -notlike "Local*" `
            -and $_.$MachineType -like "Server*"} | Group-Object -Property $AccountName | 
            Sort-Object -Property Count -Descending -Top 20 | Select-Object Count,Name

Write-Host ("
Domain-Based Windows Server Admins (Wide Spread Access)
This will provide you with a complete list of the domain-based server admin accounts, 
and the count of machines they have administrative access to:
-------------------------------------------------------------------------------------") -ForegroundColor Green

            $WideSpreadAccess | Format-Table -AutoSize -Property `
            @{n="Account Name";e={$_.Name};Alignment="Center"},
            @{n="Number Of Machines With Access";e={$_.Count};Alignment="Center"}

            $WideSpreadAccess2 =  $WindowsSheetData | Where-Object {$_.$AccountGroup -like "Administrators*" `
            -and $_.$AccountType -notlike "Local*" `
            -and $_.$MachineType -like "Server*"} | Group-Object -Property $AccountName | 
            Sort-Object -Property Count -Descending

            $WideSpreadAccess2 | Format-Table -AutoSize -Property `
            @{n="Account Name";e={$_.Name};Alignment="Center"},
            @{n="Number Of Servers With Access";e={$_.Count};Alignment="Center"} |
            Tee-Object -FilePath $ReportWideSpreadAccess | Out-Null
    }

    Get-WideSpreadAccess -ReportPath $ReportPath

    Function Get-WideSpreadLimitedAccess {
        param(
            [Parameter(Mandatory = $true)]
            [string]$ReportPath
            )

            $WideSpreadLimitedAccess = Join-Path "$ReportPath" "WideSpreadLimitedAccessServers.txt"

Write-Host ("
Domain-Based Windows Server Admins (with Limited Access)
This will provide you with a complete list of the domain-based server admin accounts, 
and the count of machines they have administrative access to.
Similar to the previous report but  we're looking for accounts with a smaller 
percentage of access to machines. Less than 10% is generally considered Limited Access:
---------------------------------------------------------------------------------------") -ForegroundColor Green

            $LimitedAccess =  $WindowsSheetData | Where-Object {$_.$AccountGroup -like "Administrators*" `
            -and $_.$AccountType -notlike "Local*" `
            -and $_.$MachineType -like "Server*"} | Group-Object -Property $AccountName | 
            Sort-Object -Property Count -Top 170 | Select-Object Count,Name -Last 20

            $LimitedAccess | Format-Table -AutoSize -Property `
            @{n="Account Name";e={$_.Name};Alignment="Center"},
            @{n="Number Of Machines With Access";e={$_.Count};Alignment="Center"}

            $LimitedAccess2 = $WindowsSheetData | Where-Object {$_.$AccountGroup -eq "Administrators" `
            -and $_.$AccountType -notlike "Local*" `
            -and $_.$MachineType -like "Server*"} | Group-Object -Property $AccountName | 
            Sort-Object -Property Count

            $LimitedAccess2 | Format-Table -Property `
            @{n="Account Name";e={$_.Name};Alignment="Center"},
            @{n="Number Of Servers With Access";e={$_.Count};Alignment="Center"} |
            Tee-Object -FilePath $WideSpreadLimitedAccess | Out-Null
    }

    Get-WideSpreadLimitedAccess -ReportPath $ReportPath

    Function Get-WorkstationAdmin {
            param(
                [Parameter(Mandatory = $true)]
                [string]$ReportPath
                )

            $DomainBasedWorkstationAdmins = Join-Path "$ReportPath" "WideSpreadAccessWorksations.txt"

            Write-Host ("This will give us all the domain-based accounts with admin permissions on workstations:
---------------------------------------------------------------------------------------") -ForegroundColor Green

            $WorksationAdmins =  $WindowsSheetData | Where-Object {$_.$AccountGroup -like "Administrators*" `
            -and $_.$AccountType -notlike "Local*" `
            -and $_.$MachineType -like "Workstation*"} | Group-Object -Property $AccountName |  
            Sort-Object -Property Count -Descending | Select-Object Count,Name -First 30

            $WorksationAdmins | Format-Table -Property `
            @{n="Account Name";e={$_.Name};Alignment="Center"},
            @{n="Number Of Workstations With Access";e={$_.Count};Alignment="Center"}

            $WorksationAdmins2 = $WindowsSheetData | Where-Object {$_.$AccountGroup -like "Administrators*" `
            -and $_.$AccountType -notlike "Local*" `
            -and $_.$MachineType -like "Workstation*"} | Group-Object -Property $AccountName | 
            Sort-Object -Property Count -Descending

            $WorksationAdmins2 | Format-Table -Property `
            @{n="Account Name";e={$_.Name};Alignment="Center"},
            @{n="Number Of Machines With Access";e={$_.Count};Alignment="Center"} |
            Tee-Object -FilePath $DomainBasedWorkstationAdmins | Out-Null
    }

    Get-WorkstationAdmin -ReportPath $ReportPath

    Function Get-BuiltInAdmin {
            param(
            [Parameter(Mandatory = $true)]
            [string]$ReportPath
            )

            $ReportWindowsBuiltInLocalAdmins = Join-Path "$ReportPath" "WindowsBuiltInLocalAdmins.txt"

            Write-Host ("Windows Built-in Local Administrators(SID-500)(Enabled-Only):
-------------------------------------------------------------") -ForegroundColor Green

            $WindowsBuiltInLocalAdmins =  $WindowsSheetData | Where-Object {$_.$AccountGroup -like "Administrators*" `
            -and $_.$AccountType -like "Local*" -and $_.$AccountDescription -like "Built-in account for*" `
            -and $_.$AccountState -like "Enabled*"} | 
            Select-Object -First 15

            $WindowsBuiltInLocalAdmins | Sort-Object -Property $PasswordAge -Descending | Format-Table -AutoSize -Wrap -Property `
            $HashTableAccountName,$HashTableAccountType,$HashTableAccountState,$HashTableMachineName,$HashTablePasswordAge,
            $HashTableAccountDescription

            $WindowsBuiltInLocalAdmins2 =  $WindowsSheetData | Where-Object {$_.$AccountGroup -eq "Administrators" `
            -and $_.$AccountType -like "Local*" -and $_.$AccountDescription -like "Built-in account for*" `
            -and $_.$AccountState -like "Enabled*"}

            $WindowsBuiltInLocalAdmins2 | Sort-Object -Property $PasswordAge -Descending | Format-Table -Property `
            $HashTableAccountName,$HashTableAccountType,$HashTableAccountState,$HashTableMachineName,$HashTablePasswordAge,
            $HashTableAccountDescription |
            Tee-Object -FilePath $ReportWindowsBuiltInLocalAdmins | Out-Null

    }

    Get-BuiltInAdmin -ReportPath $ReportPath

    Function Get-LocalAdmin {
            param(
                [Parameter(Mandatory = $true)]
                [string]$ReportPath
            )

            $ReportWindowsLocalAdmins = Join-Path "$ReportPath" "WindowsLocalAdmins.txt"

            Write-Host ("Windows Local Administrators(Enabled-Only), similar to our built-in Local Administrators but we are excluding the builtin ones,
this will give us all the other local admin accounts that have been created outside of that SID-500 account:
-------------------------------------------------------------------------------------------------------------------------------") `
-ForegroundColor Green

            $WindowsLocalAdmins = $WindowsSheetData | Where-Object {$_.$AccountGroup -like "Administrators*" `
            -and $_.$AccountType -like "Local*" -and $_.$AccountDescription -notlike "Built-in account for*" `
            -and $_.$AccountState -like "Enabled*"} |Select-Object -First 15

            $WindowsLocalAdmins | Sort-Object -Property $PasswordAge -Descending | Format-Table -AutoSize -Wrap -Property `
            $HashTableAccountName,$HashTableAccountType,$HashTableAccountState,$HashTableMachineName,$HashTablePasswordAge,
            $HashTableAccountDescription

            $WindowsLocalAdmins2 =  $WindowsSheetData | Where-Object {$_.$AccountGroup -like "Administrators*" `
            -and $_.$AccountType -like "Local*" -and $_.$AccountDescription -notlike "Built-in account for*" `
            -and $_.$AccountState -like "Enabled*"}

            $WindowsLocalAdmins2 | Sort-Object -Property $PasswordAge -Descending | Format-Table -Property `
            $HashTableAccountName,$HashTableAccountType,$HashTableAccountState,$HashTableMachineName,$HashTablePasswordAge,
            $HashTableAccountDescription |
            Tee-Object -FilePath $ReportWindowsLocalAdmins | Out-Null
    }

    Get-LocalAdmin -ReportPath $ReportPath

    Function Get-LocalAccountHighAge {
            param(
                [Parameter(Mandatory = $true)]
                [string]$ReportPath
            )

            $ReportHighAgeLocal = Join-Path "$ReportPath" "HighAgeLocalAccounts.txt"

            $HighAgeLocal = $WindowsSheetData | Sort-Object -Property $PasswordAge -Descending |
            Where-Object {$_.$AccountType -like "Local*" -and $_.$AccountState -like "Enabled*"} | Select-Object -First 15

            Write-Host ("Local Accounts with High Age(passwords not rotated for a long period)(Enabled only on this view):
-------------------------------------------------------------------------------------------------") `
            -ForegroundColor Green

            $HighAgeLocal | Sort-Object -Property $PasswordAge -Descending | Format-Table -Property `
            $HashTableAccountName,$HashTableAccountState,$HashTablePasswordAge,$HashTablePasswordNeverExpires

            $HighAgeLocal2 = $WindowsSheetData  | Sort-Object -Property $PasswordAge -Descending |
            Where-Object {$_.$AccountType -like "Local*"}

            $HighAgeLocal2 | Sort-Object -Property $PasswordAge -Descending | Format-Table -Property `
            $HashTableAccountName,$HashTableAccountState,$HashTablePasswordAge,$HashTablePasswordNeverExpires,
            $HashTableAccountCategory,$HashTableAccountType,$HashTableMachineName |
            Tee-Object -FilePath $ReportHighAgeLocal | Out-Null
    }

    Get-LocalAccountHighAge -ReportPath $ReportPath

    Function Get-DomainAccountHighAge {
            param(
                [Parameter(Mandatory = $true)]
                [string]$ReportPath
            )

            $ReportHighAgeDomain = Join-Path "$ReportPath" "HighAgeDomainAccounts.txt"

            $HighAgeDomain = $WindowsSheetData | Sort-Object -Property $PasswordAge -Descending -Unique |
            Where-Object {$_.$AccountType -notlike "Local*" -and $_.$AccountState -like "Enabled*"} | Select-Object -First 15

            Write-Host ("Domain Accounts with High Age(passwords not rotated for a long period)(Enabled only on this view):
--------------------------------------------------------------------------------------------------") `
            -ForegroundColor Green

            $HighAgeDomain | Sort-Object -Property $PasswordAge -Descending | Format-Table -Property `
            $HashTableAccountName,$HashTableAccountState,$HashTablePasswordAge,$HashTablePasswordNeverExpires

            $HighAgeDomain2 = $WindowsSheetData | Sort-Object -Property $PasswordAge -Descending -Unique |
            Where-Object {$_.$AccountType -notlike "Local*"}

            $HighAgeDomain2 | Sort-Object -Property $PasswordAge -Descending | Format-Table -Property `
            $HashTableAccountName,$HashTableAccountState,$HashTablePasswordAge,$HashTablePasswordNeverExpires,
            $HashTableAccountCategory,$HashTableAccountType |
            Tee-Object -FilePath $ReportHighAgeDomain | Out-Null
    }

    Get-DomainAccountHighAge -ReportPath $ReportPath

    Function Get-PassTheHashFoundYes {
            param(
                [Parameter(Mandatory = $true)]
                [string]$ReportPath
            )
            Write-Host ("Accounts and machines that can be subject to pass the hash attacks:
-------------------------------------------------------------------") -ForegroundColor Green

            $ReportPassTheHashAccounts = "$ReportPath\PassTheHashFoundYesAccounts.txt"

            $PassTheHashAccounts = $WindowsSheetData | Where-Object {$_.$PassTheHashHashFound -like "Yes*"} | 
            Select-Object -First 15

            $PassTheHashAccounts | Sort-Object -Property $PasswordAge -Descending | Format-Table -AutoSize -Wrap -Property `
            $HashTableAccountName,$HashTablePasswordAge,$HashTablePassTheHashHashFound,$HashTableAccountType,
            $HashTableAccountState,$HashTableMachineName

            $PassTheHashAccounts2 = $WindowsSheetData | Where-Object {$_.$PassTheHashHashFound -like "Yes*"}

            $PassTheHashAccounts2 | Sort-Object -Property $PasswordAge -Descending | Format-Table -AutoSize -Wrap -Property `
            $HashTableAccountName,$HashTablePasswordAge,$HashTablePassTheHashHashFound,$HashTableAccountType,
            $HashTableAccountState,$HashTableMachineName |
            Tee-Object $ReportPassTheHashAccounts | Out-Null
    }

    Get-PassTheHashFoundYes -ReportPath $ReportPath

    Function Get-HardCodedCredential {
            param(
                    [Parameter(Mandatory = $true)]
                    [string]$ReportPath
                )
                Write-Host ("Hard Coded Credentials:
-----------------------") -ForegroundColor Green

            $ReportHardCodedCredentials = Join-Path "$ReportPath" "HardCodedCredentials.txt"

            $HardCodedCredentials = $HardCodedData | Select-Object -First 7

            $HardCodedCredentials | Format-List -Property `
            $AccountName,$HardCodedFile,$HardCodedCredential,$MachineName,$ApplicationServer,
            $ApplicationName

            $HardCodedCredentials2 = $HardCodedData

            $HardCodedCredentials2 | Format-List -Property `
            $AccountName,$HardCodedFile,$HardCodedCredential,$MachineName,$ApplicationServer,
            $ApplicationName |
            Tee-Object -FilePath $ReportHardCodedCredentials | Out-Null
    }

    Get-HardCodedCredential -ReportPath $ReportPath

Write-Host ("------------------------------------------------------------------------
Full reports are saved under $ReportPath             
------------------------------------------------------------------------").Trim() -ForegroundColor Cyan

Stop-Transcript