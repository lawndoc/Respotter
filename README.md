# ![Respotter](./assets/respotter_logo.png)

## The Responder Honeypot

This application detects active instances of [Responder](https://github.com/lgandx/Responder) by taking advantage of the fact that __Responder will respond to any DNS query__. Respotter uses LLMNR, mDNS, and NBNS protols to search for a bogus hostname that does not exist (default: Loremipsumdolorsitamet). If any of the requests get a response back, then it means that Responder is likely running on your network.

Respotter can send webhooks to Slack, Teams, or Discord. It also supports sending events to a syslog server to be ingested by a SIEM. Webhooks alerts are rate limited to 1 alert per IP per hour.

## Quick start

```bash
docker run --rm --net=host ghcr.io/lawndoc/respotter
```

*Note: `--net=host` is required due to privileged socket usage when crafting request packets*

## Demo

![demo gif](./assets/respotter_demo.gif)

## Vulnerable host identification

Respotter will also listen for LLMNR, mDNS, and NBNS queries that originate from other hosts. Queries from other hosts will raise an alert warning that the host may be susceptible to credential theft from Responder. Webhook alerts for vulnerable hosts are rate limited to 1 alert per IP:Protocol per day.

Respotter does NOT attempt to poison responses to sniffed queries. Poisoning responses isn't opsec-safe for the honeypot, and may cause issues with the client. Use Responder to identify accounts that are vulnerable to poisoning once a vulnerable host has been discovered by Respotter.

## Additional configuration

Detailed information on configuration and deployment can be found in [the wiki](https://github.com/lawndoc/Respotter/wiki/Deploying-Respotter)

## License

[MIT](https://choosealicense.com/licenses/mit/)

## Contributors

This project was originally created by [Baden Erb](https://badenerb.com) ([@badenerb](https://github.com/badenerb))

Current maintainers:

* [C.J. May](https://cjmay.info) ([@lawndoc](https://github.com/lawndoc))
* [Matt Perry]() ([@xmjp](https://github.com/xmjp))
