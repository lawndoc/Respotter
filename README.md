![respotterLogo](./assets/respotter_logo.png)

# Respotter is a reliable Responder HoneyPot!

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

## FAQ

#### Question 1: How can I set this up to run as a scheduled task?

Convert the Respotter.ps1 file to a Executable file by running: 

    PS C:\> Install-Module ps2exe
    Invoke-ps2exe .\Respotter.ps1 .\Respotter.exe
Then, set up the scheduled task on this executable, in the same directory

#### Question 2: Do I need special permissions to run this?

You shouldn't, this command is just a DNS Resolution, so anyone can do it. But you may need extra permissions to run as a schedueled service.

## Demo

![demo gif](./assets/respotter_demo.gif)

https://www.youtube.com/watch?v=vcPbdAVR560&ab_channel=BadenErb


## License

[MIT](https://choosealicense.com/licenses/mit/) 

You can use this as you please!


## Feedback

If you have any feedback, please reach out to me, I am still learning and always want to be learning so feel free to shoot me an email at baden.erb@gmail.com


## Contributors

This project was originally created by [Baden Erb](https://badenerb.com) ([@badenerb](https://github.com/badenerb))

Current maintainer: [C.J. May](https://cjmay.info) ([@lawndoc](https://github.com/lawndoc))
