param ([Parameter(Mandatory=$true)] $I) 
$I = $I.Trim()
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Function submit-VT($I)
{
    $VTbody = @{resource = $I;}
    $headers=@{}
    $headers.Add("Accept", "application/json")
    $headers.Add("x-apikey", "5b8cf596a8994ff26bf56145e3531dbf6dc845ca0372476b894ae6d50d89fe25")
    $VTResult = Invoke-WebRequest -Uri "https://www.virustotal.com/api/v3/ip_addresses/$I" -Method GET -Headers $headers
    return $VTResult}

$VTresult = submit-VT($I)
#Write-Host $VTresult
$data = ConvertFrom-Json $VTresult

if ([int]$data.data.attributes.last_analysis_stats.malicious -gt 0) { $outcome = "`nThis IP has a malicious rating. Blacklisting is advised"}
else {$outcome = "`nThis IP has a neutral reputation on VirusTotal."}

## Display results
Function DisplayResults(){
    Write-Host "======================================================================="


    Write-Output @"
Source IP: $I
Country: $($data.data.attributes.country)
ASN: $($data.data.attributes.as_owner)
VirusTotal URL: https://www.virustotal.com/gui/ip-address/$I/detection
$outcome

"@ #|Set-Clipboard   #uncomment this if u want to copy contents to clipboard instead
}
    
DisplayResults 
pause
