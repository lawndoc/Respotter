import json
import requests

class TeamsException(Exception):
    pass

# You will need to edit the teams.conf file with your own webhook URL

# Sending a message to Microsoft Teams:
def send_teams_message(webhook_url, responder_ip):
    headers = {'Content-Type': 'application/json',
               'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Microsoft Windows 10.0.15063; en-US) PowerShell/6.0.0',
               }
    json_data = {
        "type": "message",
        "attachments": [
            {
                "contentType": "application/vnd.microsoft.card.adaptive",
                "contentUrl": None,
                "content": {
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "type": "AdaptiveCard",
                    "body": [
                        {
                            "type": "Image",
                            "url": "https://raw.githubusercontent.com/lawndoc/Respotter/main/assets/respotter_logo.png",
                            "altText": "Respotter Alert",
                        },
                        {
                            "type": "TextBlock",
                            "text": f"Responder instance found at {responder_ip}\n"
                        }
                    ]
                }
            }
        ]
    }
    response = requests.post(webhook_url, json=json_data, headers=headers)
    if response.status_code != 202:
        raise TeamsException(response.reason)
 
if __name__ == "__main__":
    with open("respotter.conf", "r") as config_file:
        conf = json.load(config_file)
    send_teams_message(conf["webhook_url"], "this is a test")
