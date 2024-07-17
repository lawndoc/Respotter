from discord_webhook import DiscordWebhook, DiscordEmbed

def send_discord_message(webhook_url, title, details):
    webhook = DiscordWebhook(url=webhook_url, rate_limit_retry=True)
    embed = DiscordEmbed(title=title, description=details, color=242424)
    embed.set_author(name='Respotter')
    embed.set_thumbnail(url='https://raw.githubusercontent.com/lawndoc/Respotter/main/assets/respotter_logo.png')
    webhook.add_embed(embed)
    response = webhook.execute()
    if response.status_code == 200:
        print("Message sent successfully")
    else:
        print("Failed to send message.")