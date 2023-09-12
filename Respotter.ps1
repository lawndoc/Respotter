#This function checks if the input has any comma in it and if it does, 
#it will return everything to the right of the comma, removing whitespace as well.
function Get-TextAfterComma {
    param (
        [string]$inputString
    )
    
    if ($inputString -match ',') {
        $textAfterComma = $inputString -replace '.*,\s*', ''
        return $textAfterComma
    }
    else {
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
    }
    else {
        return $inputString
    }
}

$resPath = Get-Location | Select-Object -ExpandProperty Path

# Specify the path to the JSON file
$pathToSettings = $resPath + "\config.json"
$settings = ""
# Check if the file exists
if (Test-Path $pathToSettings -PathType Leaf) {
    # Read the JSON content from the file
    $jsonContent = Get-Content $pathToSettings -Raw

    # Convert JSON to a PowerShell object
    $settings = $jsonContent | ConvertFrom-Json
}
else {
    Write-Host "The Config JSON file does not exist, please download it from the GitHub page here: https://github.com/badenerb/Respotter/blob/main/config.json and paste in the working directory. Your working directory is" $resPath
    Exit
}

if (!$settings.noOutput) {
    Write-Host "
    ____                        __  __           
   / __ \___  _________  ____  / /_/ /____  _____
  / /_/ / _ \/ ___/ __ \/ __ \/ __/ __/ _ \/ ___/
 / _, _/  __(__  ) /_/ / /_/ / /_/ /_/  __/ /    
/_/ |_|\___/____/ .___/\____/\__/\__/\___/_/     
               /_/                              
"

    Write-Host "Press enter to begin scan"
    Read-Host
}

$networkName = Get-NetConnectionProfile | Select-Object -ExpandProperty Name

if (!$settings.noOutput) {
    Write-Host "Scanning for Responder running on"$networkName"

This should only take a few seconds.
"
}

$search = (Resolve-DnsName -LlmnrOnly $settings.falseDNSName 2> $Null)
$ips = $search.IpAddress -Join ", "

if ($ips -ne "") {
    if (!$settings.ip6Only) {
        $ip4 = Get-TextAfterComma -inputString $ips
    }
    if (!$settings.ip4Only) {
        $ip6 = Get-TextBeforeComma -inputString $ips
    }
    if (!$settings.noOutput) {
        Write-Host "Responder present at: "
        if (!$settings.ip6Only) {
            Write-Host "    IP V4:" $ip4
        }
        if (!$settings.ip4Only) {
            Write-Host "    IP V6:" $ip6
        }
    }
        
    if(!$settings.webhookURI.Length -eq 0)
    {
        $jsonData = ''

        $messageCardPath = $resPath + "\messageCard.json"
        if (Test-Path $messageCardPath -PathType Leaf) {
            # Read the JSON content from the file
            $jsonData = Get-Content $messageCardPath -Raw
        }
        else {
            Write-Host "The message card JSON file does not exist, please download it from the GitHub page here: https://github.com/badenerb/Respotter/blob/main/messageCard.json and paste in the working directory.  Your working directory is" $resPath
            Exit
        }

        $messageCardJson = $jsonData | ConvertFrom-Json
        if(!$settings.ip4Only)
        {
            $messageCardJson.text ="Responder was found running at " + $ip4
        }
        elseif(!$settings.ip6Only)
        {
            $messageCardJson.text ="Responder was found running at " + $ip6
        }
        else{
            $messageCardJson.text = "Responder was found running at " + $ip4 + " " + $ip6
        }
        $messageCardFinal = $messageCardJson | ConvertTo-Json 

        $WebhookSent = Invoke-RestMethod -Uri $settings.webhookURI -Method POST -Body $messageCardFinal -ContentType "Application/Json"
    
        if($WebhookSent -eq 1)
        {
            if (!$settings.noOutput) {Write-Host "Webhook successfully posted!"}
        }
        else
        {
            if (!$settings.noOutput) {Write-Host "Webhook failed to post!"}
        }
    }
}
else {
    if (!$settings.noOutput) {
        Write-Host "Responder not found..."
    }
}

if (!$settings.noOutput) 
{
    Write-Host "Press Enter to close" 
    Read-Host
}