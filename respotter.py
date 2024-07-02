#!/usr/bin/env python3

import argparse
from ipaddress import ip_network
import json
from scapy.all import *
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, UDP
from scapy.layers.llmnr import LLMNRQuery, LLMNRResponse
from scapy.layers.netbios import NBNSQueryRequest, NBNSQueryResponse, NBNSHeader
import sys
from time import sleep
from utils.teams import send_teams_message

respotter_ascii_logo = r"""
    ____                        __  __           
   / __ \___  _________  ____  / /_/ /____  _____
  / /_/ / _ \/ ___/ __ \/ __ \/ __/ __/ _ \/ ___/
 / _, _/  __(__  ) /_/ / /_/ / /_/ /_/  __/ /    
/_/ |_|\___/____/ .___/\____/\__/\__/\___/_/     
               /_/                              
"""

class Respotter:
    def __init__(self,
                 delay=30,
                 excluded_protocols=[],
                 hostname="Loremipsumdolorsitamet",
                 subnet="",
                 timeout=1,
                 verbosity=0,
                 discord_webhook="",
                 slack_webhook="",
                 teams_webhook="",):
        conf.checkIPaddr = False  # multicast/broadcast responses won't come from dst IP
        self.delay = delay
        self.excluded_protocols = excluded_protocols
        self.hostname = hostname
        self.is_daemon = False
        self.timeout = timeout
        self.verbosity = verbosity
        if subnet:
            try:
                network = ip_network(subnet)
            except:
                print(f"[!] ERROR: could not parse subnet CIDR. Netbios protocol will be disabled.")
            self.broadcast_ip = str(network.broadcast_address)
        else:
            print(f"[!] ERROR: subnet CIDR not configured. Netbios protocol will be disabled.")
            self.excluded_protocols.append("nbns")
            
        self.webhooks = {}
        for service in ["teams", "slack", "discord"]:
            webhook = eval(f"{service}_webhook")
            if webhook:
                self.webhooks[service] = webhook
            else:
                print(f"[-] WARNING: {service} webhook URL not set")
                
    def webhook_alert(self, responder_ip):
        if "teams" in self.webhooks:
            send_teams_message(self.webhooks["teams"], responder_ip)
            
    
    def send_llmnr_request(self):
        # LLMNR uses the multicast IP 224.0.0.252 and UDP port 5355
        packet = IP(dst="224.0.0.252")/UDP(dport=5355)/LLMNRQuery(qd=DNSQR(qname=self.hostname))
        response = sr1(packet, timeout=self.timeout, verbose=0)
        if not response:
            if self.verbosity >= 1:
                print(f"[*] [LLMNR] No response for '{self.hostname}'")
            return
        if self.verbosity >=1:
            for p in response:
                print(p)
        # Print all resolved IP addresses
        for sniffed_packet in response:
            if sniffed_packet.haslayer(LLMNRResponse):
                for answer in sniffed_packet[LLMNRResponse].an:
                    if answer.type == 1:  # Type 1 is A record, which contains the IP address
                        print(f"[!] [LLMNR] Responder detected at: {answer.rdata} - responded to name '{self.hostname}'")
                        if self.is_daemon:
                            self.webhook_alert(answer.rdata)
        
    def send_mdns_request(self):
        # mDNS uses the multicast IP 224.0.0.251 and UDP port 5353
        packet = IP(dst="224.0.0.251")/UDP(dport=5353)/DNS(rd=1, qd=DNSQR(qname=self.hostname))
        response = sr1(packet, timeout=self.timeout, verbose=0)
        if not response:
            if self.verbosity >= 1:
                print(f"[*] [MDNS] No response for '{self.hostname}'")
            return
        if self.verbosity >=1:
            for p in response:
                print(p)
        # Print all resolved IP addresses
        for sniffed_packet in response:
            if sniffed_packet is not None and sniffed_packet.haslayer(DNS):
                for answer in sniffed_packet[DNS].an:
                    if answer.type == 1:
                        print(f"[!] [MDNS] Responder detected at: {answer.rdata} - responded to name '{self.hostname}'")
                        if self.is_daemon:
                            self.webhook_alert(answer.rdata)
        
    def send_nbns_request(self):
        try:
            self.broadcast_ip
        except AttributeError:
            print("[!] ERROR: broadcast IP not set. Skipping Netbios request.")
            return
        # WORKAROUND: Scapy not matching long req to resp (secdev/scapy PR #4446)
        hostname = self.hostname[:15]
        packet = IP(dst=self.broadcast_ip)/UDP(sport=137, dport=137)/NBNSHeader(OPCODE=0x0, NM_FLAGS=0x11, QDCOUNT=1)/NBNSQueryRequest(SUFFIX="file server service", QUESTION_NAME=hostname, QUESTION_TYPE="NB")
        response = sr1(packet, timeout=self.timeout, verbose=0)
        if not response:
            if self.verbosity >= 1:
                print("[*] [NBT-NS] No response for '{hostname}'")
            return
        if self.verbosity >=1:
            for p in response:
                print(p)
        # Print all resolved IP addresses
        for sniffed_packet in response:
            if sniffed_packet is not None and sniffed_packet.haslayer(NBNSQueryResponse):
                for answer in sniffed_packet[NBNSQueryResponse].ADDR_ENTRY:
                    print(f"[!] [NBT-NS] Responder detected at: {answer.NB_ADDRESS} - responded to name '{hostname}'")
                    if self.is_daemon:
                        self.webhook_alert(answer.rdata)

    
    def daemon(self):
        self.is_daemon = True
        while True:
            if "llmnr" not in self.excluded_protocols:
                self.send_llmnr_request()
            if "mdns" not in self.excluded_protocols:
                self.send_mdns_request()
            if "nbns" not in self.excluded_protocols:
                self.send_nbns_request()
            sleep(self.delay)
            
def parse_options():
    # Do argv default this way, as doing it in the functional
    # declaration sets it at compile time.
    # if argv is None:
    #     argv = sys.argv

    # add_help=False so it doesn't parse -h yet
    config_parser = argparse.ArgumentParser(add_help=False)
    config_parser.add_argument("-c", "--config", help="Specify config file", metavar="FILE")
    args, remaining_argv = config_parser.parse_known_args()

    # Precedence: defaults < config file < cli arguments
    defaults = {
        "delay": 30,
        "discord_webhook": "",
        "exclude": "",
        "hostname": "Loremipsumdolorsitamet",
        "slack_webhook": "",
        "subnet": "",
        "teams_webhook": "",
        "timeout": 1,
        "verbosity": 0,
    }

    # parse config and override defaults
    if args.config:
        with open(args.config, "r") as config_file:
            config = json.load(config_file)
        defaults.update(config)

    # parse args and override config
    parser = argparse.ArgumentParser(parents=[config_parser])
    parser.set_defaults(**defaults)
    parser.add_argument("-d", "--delay", help="Delay between scans in seconds")
    parser.add_argument("-t", "--timeout", help="Timeout for each scan in seconds")
    parser.add_argument("-s", "--subnet", help="Subnet in CIDR format to calculate broadcast IP for Netbios")
    parser.add_argument("-v", "--verbosity", help="Verbosity level (0-3)")
    parser.add_argument("-n", "--hostname", help="Hostname to scan for")
    parser.add_argument("-x", "--exclude", help="Protocols to exclude from scanning (e.g. 'llmnr,nbns')")
    args = parser.parse_args(remaining_argv)
    if int(args.verbosity) > 0:
        print(f"Final config: {args}\n")
    return args
    

if __name__ == "__main__":
    print(respotter_ascii_logo)
    print("\nScanning for Responder...\n")
    
    options = parse_options()
    
    excluded_protocols = options.exclude.split(",")
    if excluded_protocols == [""]:
        excluded_protocols = []
    for protocol in excluded_protocols:
        if protocol not in ["llmnr", "mdns", "nbns"]:
            print("[!] Error - exclusions must be a comma separated list of the following options: llmnr,mdns,nbns")
            exit(1)

    respotter = Respotter(delay=int(options.delay),
                          excluded_protocols=excluded_protocols,
                          hostname=options.hostname,
                          subnet=options.subnet,
                          timeout=int(options.timeout),
                          verbosity=int(options.verbosity),
                          discord_webhook=options.discord_webhook,
                          slack_webhook=options.slack_webhook,
                          teams_webhook=options.teams_webhook,)
    
    respotter.daemon()