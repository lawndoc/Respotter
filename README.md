![respotterLogo](./assets/respotter_logo.png)

# Respotter is a reliable Responder HoneyPot!

*status*: Respotter is currently undergoing a rewrite in Python. Basic functionality works, but new features are being added rapidly. Major changes may happen at any time.

## How it works
This application uses LLMNR, mDNS, and NBNS protols to search for a bogus hostname that does not exist (default: Loremipsumdolorsitamet). Responder "responds" to any DNS query, correct or incorrect. If the requests get a response back, then it means that Responder is likely running on your network. 

## Installation
### Docker
```bash
docker run --rm -d --net=host --name=respotter ghcr.io/lawndoc/respotter:latest
```
*Note: `--net=host` is required due to privileged socket usage when crafting request packets*

### Running locally
1. Clone the repo:
```bash
git clone https://github.com/lawndoc/Respotter
cd Respotter
```

2. Create your config file:
```bash
cp respotter.conf.template respotter.conf
vim respotter.conf
```

3. Setup a venv and run the script:
```bash
python3 -m venv venv
./venv/bin/pip install -r requirements.txt
sudo ./venv/bin/python ./respotter.py
```

## Output
When Responder is found on your network:

`[!] [<PROTOCOL>] Responder detected at: X.X.X.X - responded to name 'Loremipsumdolorsitamet'`

## Demo

![demo gif](./assets/respotter_demo.gif)

https://www.youtube.com/watch?v=vcPbdAVR560&ab_channel=BadenErb


## License

[MIT](https://choosealicense.com/licenses/mit/) 

## Contributors

This project was originally created by [Baden Erb](https://badenerb.com) ([@badenerb](https://github.com/badenerb))

Current maintainers:
* [C.J. May](https://cjmay.info) ([@lawndoc](https://github.com/lawndoc))
* [Matt Perry]() ([@xmjp](https://github.com/xmjp))
