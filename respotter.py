#!/usr/bin/env python3

import argparse
from copy import deepcopy
from datetime import datetime, timedelta
from ipaddress import ip_network
import json
from multiprocessing import Process, Lock
from pathlib import Path
from scapy.all import *
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, UDP
from scapy.layers.llmnr import LLMNRQuery, LLMNRResponse
from scapy.layers.netbios import NBNSQueryRequest, NBNSQueryResponse, NBNSHeader
from time import sleep
from utils.discord import send_discord_message
from utils.errors import WebhookException
from utils.slack import send_slack_message
from utils.teams import send_teams_message
import logging
import logging.config
import logging.handlers

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
                 verbosity=2,
                 discord_webhook="",
                 slack_webhook="",
                 teams_webhook="",
                 syslog_address="",
                 test_webhooks=False
                ):
        # initialize logger
        self.log = logging.getLogger('respotter')
        formatter = logging.Formatter('')
        handler = logging.StreamHandler()
        handler.setFormatter(formatter)
        self.log.addHandler(handler)
        self.log.setLevel((5 - verbosity) * 10)
        if syslog_address:
            handler = logging.handlers.SysLogHandler(address=(syslog_address, 514))
            formatter = logging.Formatter('Respotter {processName}[{process}]: {message}', style='{')
            handler.setFormatter(formatter)
            self.log.addHandler(handler)
        # import configuration
        self.delay = delay
        self.excluded_protocols = excluded_protocols
        self.hostname = hostname
        self.is_daemon = False
        self.timeout = timeout
        self.verbosity = verbosity
        # state persistence
        self.state_lock = Lock()
        try:
            with open("state/state.json", "r+") as state_file:
                try:
                    previous_state = json.load(state_file)
                    self.responder_alerts = previous_state["responder_alerts"]
                    self.vulnerable_alerts = previous_state["vulnerable_alerts"]
                    for ip in self.responder_alerts:
                        self.responder_alerts[ip] = datetime.fromisoformat(self.responder_alerts[ip])
                    for ip in self.vulnerable_alerts:
                        for protocol in self.vulnerable_alerts[ip]:
                            self.vulnerable_alerts[ip][protocol] = datetime.fromisoformat(self.vulnerable_alerts[ip][protocol])
                except json.JSONDecodeError:
                    raise FileNotFoundError
        except FileNotFoundError:
            self.responder_alerts = {}
            self.vulnerable_alerts = {}
            Path("state").mkdir(parents=True, exist_ok=True)
            with open("state/state.json", "w") as state_file:
                json.dump({"responder_alerts": {}, "vulnerable_alerts": {}}, state_file)
        # get broadcast IP for Netbios
        if subnet:
            try:
                network = ip_network(subnet)
            except:
                self.log.error(f"[!] ERROR: could not parse subnet CIDR. Netbios protocol will be disabled.")
            self.broadcast_ip = str(network.broadcast_address)
        elif "nbns" not in self.excluded_protocols:
            self.log.error(f"[!] ERROR: subnet CIDR not configured. Netbios protocol will be disabled.")
            self.excluded_protocols.append("nbns")
        # setup webhooks
        self.webhooks = {}
        for service in ["teams", "slack", "discord"]:
            webhook = eval(f"{service}_webhook")
            if webhook:
                self.webhooks[service] = webhook
            else:
                self.log.warning(f"[-] WARNING: {service} webhook URL not set")
        if test_webhooks:
            self.webhook_test()
            
    def webhook_test(self):
        title = "Test message"
        details = "Respotter is starting up... This is a test message."
        for service in ["teams", "discord", "slack"]:
            if service in self.webhooks:
                try:
                    eval(f"send_{service}_message")(self.webhooks[service], title=title, details=details)
                    self.log.info(f"[+] {service.capitalize()} webhook test successful")
                except WebhookException as e:
                    self.log.error(f"[!] {service.capitalize()} webhook test failed: {e}")
                
    def webhook_responder_alert(self, responder_ip):
        if responder_ip in self.responder_alerts:
            if self.responder_alerts[responder_ip] > datetime.now() - timedelta(hours=1):
                return
        title = "Responder detected!"
        details = f"Responder instance found at {responder_ip}"
        for service in ["teams", "discord", "slack"]:
            if service in self.webhooks:
                try:
                    eval(f"send_{service}_message")(self.webhooks[service], title=title, details=details)
                    self.log.info(f"[+] Alert sent to {service.capitalize()} for {responder_ip}")
                except WebhookException as e:
                    self.log.error(f"[!] {service.capitalize()} webhook failed: {e}")
        self.responder_alerts[responder_ip] = datetime.now()
        with self.state_lock:
            with open("state/state.json", "r+") as state_file:
                state = json.load(state_file)
                new_state = deepcopy(self.responder_alerts)
                for ip in new_state:
                    new_state[ip] = new_state[ip].isoformat()
                state["responder_alerts"] = new_state
                state_file.seek(0)
                json.dump(state, state_file)
        
    def webhook_sniffer_alert(self, protocol, requester_ip, requested_hostname):
        if requester_ip in self.vulnerable_alerts:
            if protocol in self.vulnerable_alerts[requester_ip]:
                if self.vulnerable_alerts[requester_ip][protocol] > datetime.now() - timedelta(days=1):
                    return
        title = f"Vulnerable host detected!"
        details = f"{protocol.upper()} query for '{requested_hostname}' from {requester_ip} - potentially vulnerable to Responder"
        for service in ["teams", "discord", "slack"]:
            if service in self.webhooks:
                try:
                    eval(f"send_{service}_message")(self.webhooks[service], title=title, details=details)
                    self.log.info(f"[+] Alert sent to {service.capitalize()} for {requester_ip}")
                except WebhookException as e:
                    self.log.error(f"[!] {service.capitalize()} webhook failed: {e}")
        if requester_ip in self.vulnerable_alerts:
            self.vulnerable_alerts[requester_ip][protocol] = datetime.now()
        else:
            self.vulnerable_alerts[requester_ip] = {protocol: datetime.now()}
        with self.state_lock:
            with open("state/state.json", "r+") as state_file:
                state = json.load(state_file)
                new_state = deepcopy(self.vulnerable_alerts)
                for ip in new_state:
                    for protocol in new_state[ip]:
                        new_state[ip][protocol] = new_state[ip][protocol].isoformat()
                state["vulnerable_alerts"] = new_state
                state_file.seek(0)
                json.dump(state, state_file)
    
    def send_llmnr_request(self):
        # LLMNR uses the multicast IP 224.0.0.252 and UDP port 5355
        packet = IP(dst="224.0.0.252")/UDP(dport=5355)/LLMNRQuery(qd=DNSQR(qname=self.hostname))
        response = sr1(packet, timeout=self.timeout, verbose=0)
        if not response:
            self.log.debug(f"[*] [LLMNR] No response for '{self.hostname}'")
            return
        for p in response:
            self.log.debug(p)
        # Print all resolved IP addresses
        for sniffed_packet in response:
            if sniffed_packet.haslayer(LLMNRResponse):
                for answer in sniffed_packet[LLMNRResponse].an:
                    if answer.type == 1:  # Type 1 is A record, which contains the IP address
                        self.log.critical(f"[!] [LLMNR] Responder detected at: {answer.rdata} - responded to name '{self.hostname}'")
                        if self.is_daemon:
                            self.webhook_responder_alert(answer.rdata)
        
    def send_mdns_request(self):
        # mDNS uses the multicast IP 224.0.0.251 and UDP port 5353
        packet = IP(dst="224.0.0.251")/UDP(dport=5353)/DNS(rd=1, qd=DNSQR(qname=self.hostname))
        response = sr1(packet, timeout=self.timeout, verbose=0)
        if not response:
            self.log.debug(f"[*] [MDNS] No response for '{self.hostname}'")
            return
        for p in response:
            self.log.debug(p)
        # Print all resolved IP addresses
        for sniffed_packet in response:
            if sniffed_packet is not None and sniffed_packet.haslayer(DNS):
                for answer in sniffed_packet[DNS].an:
                    if answer.type == 1:
                        self.log.critical(f"[!] [MDNS] Responder detected at: {answer.rdata} - responded to name '{self.hostname}'")
                        if self.is_daemon:
                            self.webhook_responder_alert(answer.rdata)
        
    def send_nbns_request(self):
        try:
            self.broadcast_ip
        except AttributeError:
            self.log.error("[!] ERROR: broadcast IP not set. Skipping Netbios request.")
            return
        # WORKAROUND: Scapy not matching long req to resp (secdev/scapy PR #4446)
        hostname = self.hostname[:15]
        # Netbios uses the broadcast IP and UDP port 137
        packet = IP(dst=self.broadcast_ip)/UDP(sport=137, dport=137)/NBNSHeader(OPCODE=0x0, NM_FLAGS=0x11, QDCOUNT=1)/NBNSQueryRequest(SUFFIX="file server service", QUESTION_NAME=hostname, QUESTION_TYPE="NB")
        response = sr1(packet, timeout=self.timeout, verbose=0)
        if not response:
            self.log.debug("[*] [NBT-NS] No response for '{hostname}'")
            return
        for p in response:
            self.log.debug(p)
        # Print all resolved IP addresses
        for sniffed_packet in response:
            if sniffed_packet is not None and sniffed_packet.haslayer(NBNSQueryResponse):
                for answer in sniffed_packet[NBNSQueryResponse].ADDR_ENTRY:
                    self.log.critical(f"[!] [NBT-NS] Responder detected at: {answer.NB_ADDRESS} - responded to name '{hostname}'")
                    if self.is_daemon:
                        self.webhook_responder_alert(answer.NB_ADDRESS)
    
    def daemon(self):
        self.is_daemon = True
        scanner_process = Process(target=self.responder_scan)
        scanner_process.start()
        sniffer_process = Process(target=self.vuln_sniff)
        sniffer_process.start()
        scanner_process.join()
        sniffer_process.join()
        
    def responder_scan(self):
        self.log.info("[*] Responder scans started")
        # Scapy setting -- multicast/broadcast responses won't come from dst IP
        conf.checkIPaddr = False
        while True:
            if "llmnr" not in self.excluded_protocols:
                self.send_llmnr_request()
            if "mdns" not in self.excluded_protocols:
                self.send_mdns_request()
            if "nbns" not in self.excluded_protocols:
                self.send_nbns_request()
            sleep(self.delay)
        
    def vuln_sniff(self):
        """
        This sniffer will NOT poison responses; it will only listen for queries.
        Poisoning responses isn't opsec-safe for the honeypot, and may cause issues with
        the client. Use Responder to identify accounts that are vulnerable to poisoning
        once a vulnerable host has been discovered by Respotter.
        """
        llmnr_sniffer = AsyncSniffer(
            filter="udp port 5355",
            lfilter=lambda pkt: pkt.haslayer(LLMNRQuery), # TODO: should this be DNSQR?
            started_callback=self.sniffer_startup,
            prn=self.llmnr_found,
            store=0
        )
        mdns_sniffer = AsyncSniffer(
            filter="udp port 5353",
            lfilter=lambda pkt: pkt.haslayer(DNS), # TODO: should this be DNSQR?
            started_callback=self.sniffer_startup,
            prn=self.mdns_found,
            store=0
        )
        nbns_sniffer = AsyncSniffer(
            filter="udp port 137",
            lfilter=lambda pkt: pkt.haslayer(NBNSQueryRequest),
            started_callback=self.sniffer_startup,
            prn=self.nbns_found,
            store=0
        )
        llmnr_sniffer.start()
        mdns_sniffer.start()
        nbns_sniffer.start()
        while True:
            sleep(1)
        
    def sniffer_startup(self):
        self.log.info("[*] Sniffer started")
        
    def llmnr_found(self, packet):
        for dns_packet in packet[LLMNRQuery].qd:
            requested_hostname = dns_packet.qname.decode()
            if requested_hostname == self.hostname + ".":
                return
            self.log.critical(f"[!] [LLMNR] LLMNR query for '{requested_hostname}' from {packet[IP].src} - potentially vulnerable to Responder")
            if self.is_daemon:
                self.webhook_sniffer_alert("LLMNR", packet[IP].src, requested_hostname)
    
    def mdns_found(self, packet):
        for dns_packet in packet[DNS].qd:
            requested_hostname = dns_packet.qname.decode()
            if requested_hostname == self.hostname + ".":
                return
            self.log.critical(f"[!] [MDNS] mDNS query for '{requested_hostname}' from {packet[IP].src} - potentially vulnerable to Responder")
            if self.is_daemon:
                self.webhook_sniffer_alert("mDNS", packet[IP].src, requested_hostname)
    
    def nbns_found(self, packet):
        requested_hostname = packet[NBNSQueryRequest].QUESTION_NAME.decode()
        if requested_hostname == self.hostname[:15]:
            return
        self.log.critical(f"[!] [NBT-NS] NBT-NS query for '{requested_hostname}' from {packet[IP].src} - potentially vulnerable to Responder")
        if self.is_daemon:
            self.webhook_sniffer_alert("Netbios", packet[IP].src, requested_hostname)
            
def parse_options():
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
        "syslog_address": "",
        "teams_webhook": "",
        "test_webhooks": False,
        "timeout": 1,
        "verbosity": 2,
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
    parser.add_argument("-v", "--verbosity", help="Verbosity level (0-5)")
    parser.add_argument("-n", "--hostname", help="Hostname to scan for")
    parser.add_argument("-x", "--exclude", help="Protocols to exclude from scanning (e.g. 'llmnr,nbns')")
    parser.add_argument("-l", "--syslog-address", help="Syslog server address")
    parser.add_argument("--test-webhooks", action="store_true", help="Test configured webhooks")
    args = parser.parse_args(remaining_argv)
    if int(args.verbosity) > 4:
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
                          teams_webhook=options.teams_webhook,
                          syslog_address=options.syslog_address,
                          test_webhooks=options.test_webhooks
                          )
    
    respotter.daemon()