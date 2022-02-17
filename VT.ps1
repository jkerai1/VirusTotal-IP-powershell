param ([Parameter(Mandatory=$true)] $I)  #139.45.197.253
## Set TLS 1.2
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Function submit-VT($I)
{
    $VTbody = @{resource = $I; "X-Apikey" = "KKEY GOES HERE"}
    $headers=@{}
    $headers.Add("Accept", "application/json")
    $headers.Add("x-apikey", "5b8cf596a8994ff26bf56145e3531dbf6dc845ca0372476b894ae6d50d89fe25")
    $VTResult = Invoke-WebRequest -Uri "https://www.virustotal.com/api/v3/ip_addresses/$I" -Method GET -Headers $headers
    return $VTResult
}
$VTresult = submit-VT($I)
Write-Host $VTresult
