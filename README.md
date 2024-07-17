# ![Respotter](./assets/respotter_logo.png)

## The Responder Honeypot

This application detects active instances of [Responder](https://github.com/lgandx/Responder) by taking advantage of the fact that __Responder will respond to any DNS query__. Respotter uses LLMNR, mDNS, and NBNS protols to search for a bogus hostname that does not exist (default: Loremipsumdolorsitamet). If any of the requests get a response back, then it means that Responder is likely running on your network.

## Quick start

```bash
docker run --rm --net=host ghcr.io/lawndoc/respotter
```

*Note: `--net=host` is required due to privileged socket usage when crafting request packets*

## Demo

![demo gif](./assets/respotter_demo.gif)

## Additional configuration

Respotter can send webhooks to Slack, Teams, or Discord. It also supports sending events to a syslog server to be ingested by a SIEM.

Detailed information on configuration and deployment can be found in [the wiki](https://github.com/lawndoc/Respotter/wiki/Deploying-Respotter)

## License

[MIT](https://choosealicense.com/licenses/mit/)

## Contributors

This project was originally created by [Baden Erb](https://badenerb.com) ([@badenerb](https://github.com/badenerb))

Current maintainers:

* [C.J. May](https://cjmay.info) ([@lawndoc](https://github.com/lawndoc))
* [Matt Perry]() ([@xmjp](https://github.com/xmjp))
