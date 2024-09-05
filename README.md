# ![Respotter](./assets/respotter_logo.png)

## The Responder Honeypot

This application detects active instances of [Responder](https://github.com/lgandx/Responder) by taking advantage of the fact that __Responder will respond to any DNS query__. Respotter uses LLMNR, mDNS, and NBNS protocols to search for a bogus hostname that does not exist (default: Loremipsumdolorsitamet). If any of the requests get a response back, then it means Responder is probably running on your network.

Respotter can send webhooks to Slack, Teams, or Discord. It also supports sending events to a syslog server to be ingested by a SIEM. Webhooks alerts are rate limited to 1 alert per IP per hour.

## Quick start

```bash
docker run --rm --net=host ghcr.io/lawndoc/respotter
```

*Note: `--net=host` is required due to privileged socket usage when crafting request packets*

## Demo

![demo gif](./assets/respotter_demo.gif)

## Advice for disabling vulnerable protocols

Respotter tells you what will break if you disable LLMNR, mDNS, and Netbios protocols on your network devices. If any name queries are found that need to be addressed, Respotter will tell you how to fix it. Once no more remediation advice is given, you can safely disable LLMNR, mDNS, and Netbios on all hosts in Respotter's subnet.

Respotter will log all sniffed queries, but it does NOT attempt to poison responses to them. Use Responder to identify accounts that are vulnerable to poisoning once a vulnerable host has been discovered by Respotter.

## Other notes

Tools that are similar to Responder such as [Inveigh](https://github.com/Kevin-Robertson/Inveigh) can also be detected because they perform similar spoofing attacks. See [LLMNR/NTB-NS Poisoning](https://attack.mitre.org/techniques/T1557/001/) on Mitre ATT&CK for more details.

## Additional configuration

Detailed information on configuration and deployment can be found in [the wiki](https://github.com/lawndoc/Respotter/wiki/Deploying-Respotter)

## License

[MIT](https://choosealicense.com/licenses/mit/)

## Contributors

This project was originally created by [Baden Erb](https://badenerb.com) ([@badenerb](https://github.com/badenerb))

Current maintainers:

* [C.J. May](https://cjmay.info) ([@lawndoc](https://github.com/lawndoc))
* [Matt Perry]() ([@xmjp](https://github.com/xmjp))
