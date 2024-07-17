from slack_sdk import WebhookClient
from slack_sdk.errors import SlackApiError
import time

def send_slack_message(webhook_url, title, details):
    client = WebClient(webhook_url)
    response = client.send(
        text=f"{title}\n{details}"
    )
    if response['ok']:
        print("Message sent successfully")
    if e.response.status_code == 429:
        # Slack rate limits to one message per channel per second, with short bursts of >1 allowed
        retry_after = int(e.response.headers['Retry-After'])
        print(f"Rate limited. Retrying in {retry_after} seconds")
        time.sleep(retry_after)
        send_slack_message(webhook_url, title, details)
    else :
        print(f"Failed to send message: {e.response.status_code}")