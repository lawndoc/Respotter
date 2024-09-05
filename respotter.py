#!/usr/bin/env python3

import argparse
from copy import deepcopy
from datetime import datetime, timedelta
from ipaddress import ip_network
import json
from multiprocessing import Process, Lock
from pathlib import Path
import random
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
                 discord_webhook="",
                 excluded_protocols=[],
                 hostname="Loremipsumdolorsitamet",
                 slack_webhook="",
                 state_file="state/state.json",
                 subnet="",
                 syslog_address="",
                 teams_webhook="",
                 test_webhooks=False,
                 verbosity=2,
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
        self.excluded_protocols = excluded_protocols
        self.hostname = hostname
        if self.hostname == "Loremipsumdolorsitamet":
            self.log.warning("[-] WARNING: using default hostname 'Loremipsumdolorsitamet' - set a more believable hostname for better OPSEC")
        self.is_daemon = False
        self.verbosity = verbosity
        # state persistence
        self.state_file = state_file
        self.state_lock = Lock()
        try:
            with open(self.state_file, "r+") as state_file:
                try:
                    previous_state = json.load(state_file)
                    self.responder_alerts = previous_state["responder_alerts"]
                    self.remediation_alerts = previous_state["remediation_alerts"]
                    for ip in self.responder_alerts:
                        self.responder_alerts[ip] = datetime.fromisoformat(self.responder_alerts[ip])
                    for ip in self.remediation_alerts:
                        self.remediation_alerts[ip] = datetime.fromisoformat(self.remediation_alerts[ip])
                except json.JSONDecodeError:
                    raise FileNotFoundError
        except FileNotFoundError:
            self.responder_alerts = {}
            self.remediation_alerts = {}
            Path("state").mkdir(parents=True, exist_ok=True)
            with open(self.state_file, "w") as state_file:
                json.dump({"responder_alerts": {}, "remediation_alerts": {}}, state_file)
        # get broadcast IP for Netbios
        if subnet:
            try:
                network = ip_network(subnet)
                self.broadcast_ip = str(network.broadcast_address)
            except:
                self.log.error(f"[!] ERROR: could not parse subnet CIDR. Netbios protocol will be disabled.")
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
        with self.state_lock:
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
            with open(self.state_file, "r+") as state_file:
                state = json.load(state_file)
                new_state = deepcopy(self.responder_alerts)
                for ip in new_state:
                    new_state[ip] = new_state[ip].isoformat()
                state["responder_alerts"] = new_state
                state_file.seek(0)
                json.dump(state, state_file)
                
    def webhook_remediation_alert(self, requester_ip, message):
        with self.state_lock:
            if requester_ip in self.remediation_alerts:
                if self.remediation_alerts[requester_ip] > datetime.now() - timedelta(hours=1):
                    return
            title = "Configuration issue detected!"
            details = message
            for service in ["teams", "discord", "slack"]:
                if service in self.webhooks:
                    try:
                        eval(f"send_{service}_message")(self.webhooks[service], title=title, details=details)
                        self.log.info(f"[+] Remediation alert sent to {service.capitalize()} for {requester_ip}")
                    except WebhookException as e:
                        self.log.error(f"[!] {service.capitalize()} webhook failed: {e}")
            self.remediation_alerts[requester_ip] = datetime.now()
            with open(self.state_file, "r+") as state_file:
                state = json.load(state_file)
                new_state = deepcopy(self.remediation_alerts)
                for ip in new_state:
                    new_state[ip] = new_state[ip].isoformat()
                state["remediation_alerts"] = new_state
                state_file.seek(0)
                json.dump(state, state_file)
    
    def send_llmnr_request(self, hostname=""):
        # LLMNR uses the multicast IP 224.0.0.252 and UDP port 5355
        if not hostname:
            hostname = self.hostname
        packet = IP(dst="224.0.0.252")/UDP(dport=5355)/LLMNRQuery(qd=DNSQR(qname=hostname))
        response = sr1(packet, timeout=1, verbose=0)
        if not response:
            self.log.debug(f"[*] [LLMNR] No response for '{hostname}'")
            return
        for p in response:
            self.log.debug(p)
        # Print all resolved IP addresses
        for sniffed_packet in response:
            if sniffed_packet.haslayer(LLMNRResponse):
                for answer in sniffed_packet[LLMNRResponse].an:
                    if answer.type == 1:  # Type 1 is A record, which contains the IP address
                        self.log.critical(f"[!] [LLMNR] Responder detected at: {answer.rdata} - responded to name '{hostname}'")
                        if self.is_daemon:
                            self.webhook_responder_alert(answer.rdata)
        
    def send_mdns_request(self, hostname=""):
        # mDNS uses the multicast IP 224.0.0.251 and UDP port 5353
        if not hostname:
            hostname = self.hostname
        packet = IP(dst="224.0.0.251")/UDP(dport=5353)/DNS(rd=1, qd=DNSQR(qname=hostname))
        response = sr1(packet, timeout=1, verbose=0)
        if not response:
            self.log.debug(f"[*] [MDNS] No response for '{hostname}'")
            return
        for p in response:
            self.log.debug(p)
        # Print all resolved IP addresses
        for sniffed_packet in response:
            if sniffed_packet is not None and sniffed_packet.haslayer(DNS):
                for answer in sniffed_packet[DNS].an:
                    if answer.type == 1:
                        self.log.critical(f"[!] [MDNS] Responder detected at: {answer.rdata} - responded to name '{hostname}'")
                        if self.is_daemon:
                            self.webhook_responder_alert(answer.rdata)
        
    def send_nbns_request(self, hostname=""):
        try:
            self.broadcast_ip
        except AttributeError:
            self.log.error("[!] ERROR: broadcast IP not set. Skipping Netbios request.")
            return
        if not hostname:
            hostname = self.hostname
        # WORKAROUND: Scapy not matching long req to resp (secdev/scapy PR #4446)
        if len(hostname) > 15:
            hostname = hostname[:15]
        # Netbios uses the broadcast IP and UDP port 137
        packet = IP(dst=self.broadcast_ip)/UDP(sport=137, dport=137)/NBNSHeader(OPCODE=0x0, NM_FLAGS=0x11, QDCOUNT=1)/NBNSQueryRequest(SUFFIX="file server service", QUESTION_NAME=hostname, QUESTION_TYPE="NB")
        response = sr1(packet, timeout=1, verbose=0)
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
            sleep(random.randrange(30,90))
        
    def vuln_sniff(self):
        """
        This sniffer will NOT poison responses; it will only listen for queries.
        Poisoning responses isn't opsec-safe for the honeypot, and may cause issues with
        the client. Use Responder to identify accounts that are vulnerable to poisoning
        once a vulnerable host has been discovered by Respotter.
        """
        llmnr_sniffer = AsyncSniffer(
            filter="udp port 5355",
            lfilter=lambda pkt: pkt.haslayer(LLMNRQuery) and pkt[IP].src != conf.iface.ip, # TODO: should this be DNSQR?
            started_callback=self.sniffer_startup,
            prn=self.llmnr_found,
            store=0
        )
        mdns_sniffer = AsyncSniffer(
            filter="udp port 5353",
            lfilter=lambda pkt: pkt.haslayer(DNS) and pkt[IP].src != conf.iface.ip, # TODO: should this be DNSQR?
            started_callback=self.sniffer_startup,
            prn=self.mdns_found,
            store=0
        )
        nbns_sniffer = AsyncSniffer(
            filter="udp port 137",
            lfilter=lambda pkt: pkt.haslayer(NBNSQueryRequest) and pkt[IP].src != conf.iface.ip,
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
            requester_ip = packet[IP].src
            requested_hostname = dns_packet.qname.decode()
            self.log.critical(f"[!] [LLMNR] LLMNR query for '{requested_hostname}' from {requester_ip} - potentially vulnerable to Responder")
            if self.is_daemon:
                self.get_remediation_advice("LLMNR", requester_ip, requested_hostname)
    
    def mdns_found(self, packet):
        for dns_packet in packet[DNS].qd:
            requester_ip = packet[IP].src
            requested_hostname = dns_packet.qname.decode()
            self.log.critical(f"[!] [MDNS] mDNS query for '{requested_hostname}' from {requester_ip} - potentially vulnerable to Responder")
            if self.is_daemon:
                self.get_remediation_advice("MDNS", requester_ip, requested_hostname)
    
    def nbns_found(self, packet):
        requester_ip = packet[IP].src
        requested_hostname = packet[NBNSQueryRequest].QUESTION_NAME.decode()
        self.log.critical(f"[!] [NBT-NS] NBT-NS query for '{requested_hostname}' from {requester_ip} - potentially vulnerable to Responder")
        if self.is_daemon:
            self.get_remediation_advice("NBT-NS", requester_ip, requested_hostname)
            
    def get_remediation_advice(self, protocol, requester_ip, requested_hostname):
        if ip := self.dns_lookup(requested_hostname):
            if ip == requester_ip:
                # Host looking for itself
                self.log.debug(f"[*] [{protocol}] {requester_ip} is looking for itself")
                return None
            elif protocol == "NBT-NS":
                # Netbios sometimes is used before doing a DNS lookup
                return None
            else:
                # Host looking for another device
                self.log.info(f"[*] [{protocol}] {requester_ip} has incorrect DNS server for {requested_hostname}")
                advice = f"{requester_ip} unable to find host '{requested_hostname}' in DNS so it used {protocol}. Update the DNS settings on {requester_ip} to point to the correct DNS server"
                self.webhook_remediation_alert(requester_ip, advice)
        else:
            if self.device_exists(requested_hostname):
                # We got a response -- DNS server is missing a record for the host
                self.log.info(f"[*] [{protocol}] DNS record missing for '{requested_hostname}' - add record to DNS server")
                advice = f"{requester_ip} unable to find host '{requested_hostname}' in DNS so it used {protocol}. Add a DNS record for '{requested_hostname}' to the DNS server"
                self.webhook_remediation_alert(requester_ip, advice)
            else:
                # We got no response -- the device doesn't exist
                self.log.debug(f"[*] [{protocol}] {requester_ip} is looking for non-existent device {requested_hostname}")

    def dns_lookup(self, hostname):
        try:
            return socket.gethostbyname(hostname)
        except:
            return None
        
    def device_exists(self, hostname):
        # LLMNR
        packet = IP(dst="224.0.0.252")/UDP(dport=5355)/LLMNRQuery(qd=DNSQR(qname=hostname))
        response = sr1(packet, timeout=1, verbose=0)
        if response:
            return True
        # mDNS
        packet = IP(dst="224.0.0.251")/UDP(dport=5353)/DNS(rd=1, qd=DNSQR(qname=hostname))
        response = sr1(packet, timeout=1, verbose=0)
        if response:
            return True
        # Netbios
        try:
            self.broadcast_ip
        except AttributeError:
            return False
        # WORKAROUND: Scapy not matching long req to resp (secdev/scapy PR #4446)
        if len(hostname) > 15:
            hostname = hostname[:15]
        packet = IP(dst=self.broadcast_ip)/UDP(sport=137, dport=137)/NBNSHeader(OPCODE=0x0, NM_FLAGS=0x11, QDCOUNT=1)/NBNSQueryRequest(SUFFIX="file server service", QUESTION_NAME=hostname, QUESTION_TYPE="NB")
        response = sr1(packet, timeout=1, verbose=0)
        if response:
            return True
        return False
        
            
def parse_options():
    # add_help=False so it doesn't parse -h yet
    config_parser = argparse.ArgumentParser(add_help=False)
    config_parser.add_argument("-c", "--config", help="Specify config file", metavar="FILE")
    args, remaining_argv = config_parser.parse_known_args()

    # Precedence: defaults < config file < cli arguments
    defaults = {
        "discord_webhook": "",
        "exclude": "",
        "hostname": "Loremipsumdolorsitamet",
        "slack_webhook": "",
        "state_file": "state/state.json",
        "subnet": "",
        "syslog_address": "",
        "teams_webhook": "",
        "test_webhooks": False,
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
    parser.add_argument("-s", "--subnet", help="Subnet in CIDR format to calculate broadcast IP for Netbios")
    parser.add_argument("-v", "--verbosity", help="Verbosity level (0-5)")
    parser.add_argument("-n", "--hostname", help="Hostname to scan for")
    parser.add_argument("-x", "--exclude", help="Protocols to exclude from scanning (e.g. 'llmnr,nbns')")
    parser.add_argument("-l", "--syslog-address", help="Syslog server address")
    parser.add_argument("--test-webhooks", action="store_true", help="Test configured webhooks")
    parser.add_argument("--state-file", help="Path to state file")
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

    respotter = Respotter(discord_webhook=options.discord_webhook,
                          excluded_protocols=excluded_protocols,
                          hostname=options.hostname,
                          slack_webhook=options.slack_webhook,
                          state_file=options.state_file,
                          subnet=options.subnet,
                          syslog_address=options.syslog_address,
                          teams_webhook=options.teams_webhook,
                          test_webhooks=options.test_webhooks,
                          verbosity=int(options.verbosity)
                          )
    
    respotter.daemon()