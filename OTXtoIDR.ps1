#NAME:  OTXtoIDR
#AUTHOR: David Reed, @ReedTechno
#LASTEDIT: 12/1/2017 11:41
#Refrences: https://insightidr.help.rapid7.com/docs/threats

### Required ###

# How far back do you wanna go for first import?
$StartingDate = "2017-11-29T11:35:40.9079652-05:00"
# From AlienVault free account - https://otx.alienvault.com/settings
$OTXAPI = ""
# From Rapid7 threat feed
$Rapid7API = ""

### End Required ###

if(Test-Path C:\temp\OTXLastRun.txt){
    $LastRunDate = Get-Content C:\temp\OTXLastRun.txt
}Else{
    $LastRunDate = $StartingDate
}
$Results =  Invoke-WebRequest "https://otx.alienvault.com:443/api/v1/indicators/export?modified_since=$LastRunDate&types=IPv4,hostname,domain,filehash-md5" -H @{"X-OTX-API-KEY" = "$OTXAPI"} | Select-Object -ExpandProperty Content
$comma = 0
ConvertFrom-Json $results | Select-Object -expand results | Select-Object -ExpandProperty indicator | ForEach-Object {
    
    If( $comma -eq 0){
    $String = $_
    $comma++
    }Else{

    $String +=", "+$_
    }
}
Invoke-WebRequest https://us.idr.insight.rapid7.com/api/1/remote/customthreat/csv/$Rapid7API/add -ContentType "text/csv" -Method POST -Body $String
Get-Date -format o | Out-file C:\temp\OTXLastRun.txt


Write-Host "IOCs uploaded:"
ConvertFrom-Json $results | Select-Object -expand results | Select-Object -ExpandProperty indicator

