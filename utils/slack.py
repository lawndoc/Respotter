from errors import WebhookException
from slack_sdk import WebhookClient
from slack_sdk.errors import SlackApiError
import time

def send_slack_message(webhook_url, title, details):
    client = WebhookClient(webhook_url)
    try:
        response = client.send(
            text=f"{title}\n{details}",
            blocks=[
                {
                    "type": "image",
                    "image_url": "https://raw.githubusercontent.com/lawndoc/Respotter/main/assets/respotter_logo.png",
                    "alt_text": "Respotter"
                },
                {  
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"_*{title}*_\n\n{details}",
                    }
                }
            ]
        )
        if response.status_code == 200:
            pass
        else:
            raise WebhookException(f"Failed to send message to Slack. Status code: {response.status_code}")
    except SlackApiError as e:        
        if e.response.status_code == 429:
            # Slack rate limits to one message per channel per second, with short bursts of >1 allowed
            retry_after = int(e.response.headers['Retry-After'])
            time.sleep(retry_after)
            response = client.send(
                text=f"{title}\n{details}"
                )   
        else:
            raise WebhookException(f"Failed to send message to Slack. Status code: {e.response.status_code}")