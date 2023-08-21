
$AppID = "RESTAPI"
$Safe = "RESTSAFE"
$CCPAddress = "192.168.74.155"
$Object = "Operating System-WinDomain-test222-test222"
$Url = "$CCPAddress/AIMWebService/api/Accounts?AppID=$AppID&$Safe=&Object=$Object"


Invoke-RestMethod -Method "GET" -Uri $Url

#########################

Clear-Host
$AppID = Read-Host "Type the AppID(exact name)".Trim()

$Safe = Read-Host "Type the SafeName(exact name)".Trim()

$CCPAddress = Read-Host "Type the CCP Address(FQDN or IP Address)".Trim()

$Object = Read-Host "Type the Object Name(wild card is accepted)".Trim()
$date = (Get-Date).ToString("MMddyyy")
$LogFile = "C:\Logs\$env:USERNAME\$date.txt"
Clear-Host
Write-Host 
"---------------------------------"
"AppID: $AppID"
"Safe: $Safe"
"CCP Address: $CCPAddress"
"Object: $Object"
"---------------------------------"
"CCP call being generated in 5 seconds"
"."
"."
"."

for ($second = 1; $second -le 5; $second++)
{
    Write-Host "CCP call starting in $second"
    Start-Sleep -Seconds 1
}

$Url = "$CCPAddress/AIMWebService/api/Accounts?AppID=$AppID&$Safe=&Object=$Object"
Clear-Host
Invoke-RestMethod -Method "GET" -Uri $Url | Tee-Object $LogFile

Write-Host 
"############# If you need, this CCP call is saved under $LogFile #############"