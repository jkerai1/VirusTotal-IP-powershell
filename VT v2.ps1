param ([Parameter(Mandatory=$true)] $I)  #139.45.197.253 neutral #138.128.150.133 malicious #139.45.197.253 neutral #138.128.150.133 malicious (Replace with Get-Clipboard?)
$I = $I.Trim()

## Set TLS 1.2
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

Function submit-VT($I)
{
    $VTbody = @{resource = $I;}
    $headers=@{}
    $headers.Add("Accept", "application/json")
    $headers.Add("x-apikey", "YOUR KEY GOES HERE")
    $VTResult = Invoke-WebRequest -Uri "https://www.virustotal.com/api/v3/ip_addresses/$I" -Method GET -Headers $headers
    return $VTResult}

$VTresult = submit-VT($I)
#Write-Host $VTresult
$data = ConvertFrom-Json $VTresult

if ([int]$data.data.attributes.last_analysis_stats.malicious -gt 0) { $outcome = "This IP has a malicious rating. Blacklisting is advised"}
else {$outcome = "This IP has a neutral reputation on VirusTotal."}

## Display results
Function DisplayResults(){
    Write-Host "======================================================================="
    Write-Host ""
    Write-Host "Source IP: " -NoNewline; Write-Host $I
    Write-Host "Country: " -NoNewline; Write-Host $data.data.attributes.country
    Write-Host "ASN: " -NoNewline; Write-Host $data.data.attributes.as_owner
    Write-Host "VirusTotal URL: " -NoNewline; Write-Host "https://www.virustotal.com/gui/ip-address/$I/detection"
    Write-Host ""
    Write-Host "$outcome"} 
    
DisplayResults
Write-Host ""
Write-Host ""
pause
