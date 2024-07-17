from slack_sdk import WebhookClient
from slack_sdk.errors import SlackApiError
import time

def send_slack_message(webhook_url, title, details):
    client = WebhookClient(webhook_url)
    try:
        response = client.send(
            text=f"{title}\n{details}"
        )
        if response.status_code == 200:
            print("Message sent successfully")
    except SlackApiError as e:        
        if e.response.status_code == 429:
            # Slack rate limits to one message per channel per second, with short bursts of >1 allowed
            retry_after = int(e.response.headers['Retry-After'])
            print(f"Rate limited. Retrying in {retry_after} seconds")
            time.sleep(retry_after)
            response = client.send(
                text=f"{title}\n{details}"
                )   
        else :
            print(f"Failed to send message: {e.response.status_code}")