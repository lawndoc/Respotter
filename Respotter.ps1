Write-Host "

    ____                        __  __           
   / __ \___  _________  ____  / /_/ /____  _____
  / /_/ / _ \/ ___/ __ \/ __ \/ __/ __/ _ \/ ___/
 / _, _/  __(__  ) /_/ / /_/ / /_/ /_/  __/ /    
/_/ |_|\___/____/ .___/\____/\__/\__/\___/_/     
               /_/                              
     

Press enter to begin scan

"
Read-Host
$networkName = Get-NetConnectionProfile | Select-Object -ExpandProperty Name
Write-Host "Scanning for Responder running on"$networkName"

This should only take a few seconds.

"

$search = (Resolve-DnsName -LlmnrOnly Loremipsumdolorsitamet 2> $Null)
$ips = $search.IpAddress -Join ", "

if($ips -ne "")
{
    $ip4 = Get-TextAfterComma -inputString $ips
    $ip6 = Get-TextBeforeComma -inputString $ips
    Write-Host "Responder present at: "
    Write-Host "    IP V4:" $ip4
    Write-Host "    IP V6:" $ip6
}
else
{
    Write-Host "Responder not found..."
}


#This function checks if the input has any comma in it and if it does, 
#it will return everything to the right of the comma, removing whitespace as well.
function Get-TextAfterComma {
    param (
        [string]$inputString
    )
    
    if ($inputString -match ',') {
        $textAfterComma = $inputString -replace '.*,\s*', ''
        return $textAfterComma
    } else {
        return $inputString
    }
}

function Get-TextBeforeComma {
    param (
        [string]$inputString
    )
    
    if ($inputString -match ',') {
        $textBeforeComma = $inputString -replace '\s*,.*', ''
        return $textBeforeComma
    } else {
        return $inputString
    }
}