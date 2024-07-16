import json
from discord_webhook import DiscordWebhook, DiscordEmbed

def send_discord_message(webhook_url, responder_ip):
    webhook = DiscordWebhook(url=webhook_url, rate_limit_retry=True)
    embed = DiscordEmbed(title='Responder instance found', description=f"Responder instance found at {responder_ip}", color=242424)
    embed.set_author(name='Respotter')
    embed.set_thumbnail(url='https://raw.githubusercontent.com/lawndoc/Respotter/main/assets/respotter_logo.png')
    webhook.add_embed(embed)
    response = webhook.execute()
    if response.status_code == 200:
        print("Message sent successfully")
    else:
        print("Failed to send message.")

if __name__ == "__main__":
    with open("respotter.conf", "r") as config_file:
        conf = json.load(config_file)
    send_discord_message(conf["webhook_url"], "this is a test")