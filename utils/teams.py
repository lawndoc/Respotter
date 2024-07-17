import requests


def send_teams_message(webhook_url, title, details):
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
                            "wrap": True,
                            "text": details + "\n"
                        }
                    ]
                }
            }
        ]
    }
    response = requests.post(webhook_url, json=json_data, headers=headers)
    if response.status_code != 202:
        print(f"[!] ERROR: failed to send teams webhook - {response.status_code} {response.reason}")