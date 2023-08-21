
$AppID = "RESTAPI"
$Safe = "RESTSAFE"
$CCPAddress = "192.168.74.155"
#$Object = "Operating System-WinDomain-test222-test222"
$Object = "Operating*"
$Url = "$CCPAddress/AIMWebService/api/Accounts?AppID=$AppID&$Safe=&Object=$Object"


Invoke-RestMethod -Method "GET" -Uri $Url