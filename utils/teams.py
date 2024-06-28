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
        "@context": "http://schema.org/extensions",
        "@type": "MessageCard",
        "themeColor": "0072C6",
        "title": "Respotter Alert!",
        "text": "Respotter Instance found at " + responder_ip + "\n"
    }
    response = requests.post(webhook_url, json=json_data, headers=headers)
    print(response.status_code)
    if response.status_code != 200:
        raise TeamsException(response.reason)
 
if __name__ == "__main__":
    with open("respotter.conf", "r") as config_file:
        conf = json.load(config_file)
    send_teams_message(conf["webhook_url"], "this is a test")
