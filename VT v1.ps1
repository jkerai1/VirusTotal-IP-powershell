param ([Parameter(Mandatory=$true)] $I)  #139.45.197.253
## Set TLS 1.2
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Function submit-VT($I)
{
    $VTbody = @{resource = $I;}
    $headers=@{}
    $headers.Add("Accept", "application/json")
    $headers.Add("x-apikey", "KEY GOES HERE")
    $VTResult = Invoke-WebRequest -Uri "https://www.virustotal.com/api/v3/ip_addresses/$I" -Method GET -Headers $headers
    return $VTResult
}
$VTresult = submit-VT($I)
Write-Host $VTresult
