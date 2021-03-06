function Get-VirusTotalIPInfo {
[CmdletBinding()]
param (
    [Parameter(Mandatory=$true)]
    $IP
)
begin {
    $CredFile = "$env:USERPROFILE\creds\VirusTotal.xml"
    if (!(test-path $CredFile)) {
        $HeaderInfo = @{
            "x-apikey" = Read-host -AsSecureString "paste in your apikey"
        }
        $HeaderInfo | Export-Clixml -Path "$env:USERPROFILE\creds\VirusTotal.xml"
        $Header = @{
            "x-apikey" = $Headerinfo."x-apikey" | ConvertFrom-SecureString -AsPlainText
        }
    }
    else {
        $Headerfile = Import-Clixml $credfile
        $Header = @{
            "x-apikey" = $Headerfile."x-apikey" | ConvertFrom-SecureString -AsPlainText
        }
        }   
    }
process {
    $Data = Invoke-RestMethod -Headers $Header -uri "https://www.virustotal.com/api/v3/ip_addresses/$IP"
    $ListOfMalicious = New-Object -TypeName System.Collections.ArrayList
    $Actors = $Data.data.attributes.last_analysis_results | get-member -MemberType noteproperty
    $Actors.foreach({
        if ( $Data.data.attributes.last_analysis_results.$($_.name).category -eq "malicious") {
            [void]$ListOfMalicious.add($Data.data.attributes.last_analysis_results.$($_.name))
            }
            })

        if ($ListOfMalicious.count -gt 0) {
            $Outcome = "listed as malicious on the following pages, look into blacklisting"
        }
        else {
            $Outcome = "This IP has a neutral reputation on VirusTotal."
            $ListOfMalicious = $null
        }
        Write-Output "======================================"
        Write-Output @"
Source IP: $IP
Country: $($Data.data.attributes.country)
ASN:  $($Data.data.attributes.as_owner)
VirusTotal URL: https://www.virustotal.com/gui/ip-address/$IP/detection

$outcome
$listofmalicious


"@ | clip
}
}# 52.222.236.10
