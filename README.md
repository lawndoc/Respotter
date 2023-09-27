![respotterLogo](https://github.com/badenerb/Respotter/assets/97712507/62aa8d04-595f-45f5-bd28-aeda59b12626)

# Respotter is a reliable, simple, Responder HoneyPot!

## Installation
Download the entire repo as a Zip. Unzip the file. Right click the Respotter.ps1 file. Run as a Powershell Script. Four simple steps!

## Output
This script will output one of two things when ran. 

When no Responder is found on your network, 

"Responder not found..."

When Responder is found on your network, 

Responder present at: (The IP Address will then be shown here)

## How it works
This script really hinges on one PowerShell CmdLet:
```PowerShell
Resolve-DnsName -LlmnrOnly Loremipsumdolorsitamet
```
This Cmdlet in this application queiries the DNS with a bogus Domain name that does not exist, in this case: Loremipsumdolorsitamet. The output of the DNS Server's response is then analyized to see if there is a Responder running; since Responder "responds" to any DNS query, correct or incorrect.
