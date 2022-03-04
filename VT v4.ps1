While($TRUE){

function Get-VT {
[CmdletBinding()]

#https://github.com/jkerai1/VirusTotal-IP-powershell

param ([Parameter(Mandatory=$true)] $I) 
$I = $I.Trim()
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Function submit-VT($I)
{
    $VTbody = @{resource = $I;}
    $headers=@{}
    $headers.Add("Accept", "application/json")
    $headers.Add("x-apikey", "KEY GOES HERE")
    $VTResult = Invoke-WebRequest -Uri "https://www.virustotal.com/api/v3/ip_addresses/$I" -Method GET -Headers $headers
    return $VTResult}

$VTresult = submit-VT($I)
#Write-Host $VTresult
$data = ConvertFrom-Json $VTresult

if ([int]$data.data.attributes.last_analysis_stats.malicious -gt 0) { $outcome = "`nThis IP has a malicious rating. Blacklisting is advised."}
else {$outcome = "`nThis IP has a neutral reputation on VirusTotal.`n"}

## Display results
Function DisplayResults(){
    Write-Host "=======================================================================`n"


    $mystring = @"
Source IP: $I
Country: $($data.data.attributes.country)
ASN: $($data.data.attributes.as_owner)
VirusTotal URL: https://www.virustotal.com/gui/ip-address/$I/detection
$outcome

"@
Write-Host $mystring
$mystring | set-clipboard
}
    
DisplayResults # 52.222.236.10
}
VT
pause
}
