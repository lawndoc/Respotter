#!/usr/bin/env python3

from scapy.all import *
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, UDP
from scapy.layers.llmnr import LLMNRQuery, LLMNRResponse
from scapy.layers.netbios import NBNSQueryRequest, NBNSQueryResponse, NBNSHeader
from time import sleep
from optparse import OptionParser

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
                 hostname="Loremipsumdolorsitamet",
                 timeout=1,
                 verbosity=0):
        self.delay = delay
        self.hostname = hostname
        self.timeout = timeout
        self.verbosity = verbosity
        conf.checkIPaddr = False  # multicast/broadcast responses won't come from dst IP
    
    def send_llmnr_request(self):
        # LLMNR uses the multicast IP 224.0.0.252 and UDP port 5355
        packet = IP(dst="224.0.0.252")/UDP(dport=5355)/LLMNRQuery(qd=DNSQR(qname=self.hostname))
        response = sr1(packet, timeout=self.timeout, verbose=0)
        if not response:
            if self.verbosity >= 1:
                print(f"No response (LLMNR -> {self.hostname})")
            return
        if self.verbosity >=1:
            for p in response:
                print(p)
        # Print all resolved IP addresses
        for sniffed_packet in response:
            if sniffed_packet.haslayer(LLMNRResponse):
                for answer in sniffed_packet[LLMNRResponse].an:
                    if answer.type == 1:  # Type 1 is A record, which contains the IP address
                        print(f"!!! Responder detected at: {answer.rdata} (LLMNR -> {self.hostname})")
        
    def send_mdns_request(self):
        # mDNS uses the multicast IP 224.0.0.251 and UDP port 5353
        packet = IP(dst="224.0.0.251")/UDP(dport=5353)/DNS(rd=1, qd=DNSQR(qname=self.hostname))
        response = sr1(packet, timeout=self.timeout, verbose=0)
        if not response:
            if self.verbosity >= 1:
                print(f"No response (mDNS -> {self.hostname})")
            return
        if self.verbosity >=1:
            for p in response:
                print(p)
        # Print all resolved IP addresses
        for sniffed_packet in response:
            if sniffed_packet is not None and sniffed_packet.haslayer(DNS):
                for answer in sniffed_packet[DNS].an:
                    if answer.type == 1:
                        print(f"!!! Responder detected at: {answer.rdata} (mDNS -> {self.hostname})")
        
    def send_nbns_request(self):
        # change IP(dst= to your local broadcast IP
        packet = IP(dst="255.255.255.255")/UDP(sport=137, dport=137)/NBNSHeader(OPCODE=0x0, NM_FLAGS=0x11, QDCOUNT=1)/NBNSQueryRequest(SUFFIX="file server service", QUESTION_NAME=self.hostname, QUESTION_TYPE="NB")
        response = sr1(packet, timeout=self.timeout, verbose=0)
        if not response:
            if self.verbosity >= 1:
                print("No response (NBNS -> {self.hostname})")
            return
        if self.verbosity >=1:
            for p in response:
                print(p)
        # Print all resolved IP addresses
        for sniffed_packet in response:
            if sniffed_packet is not None and sniffed_packet.haslayer(NBNSQueryResponse):
                for answer in sniffed_packet[NBNSQueryResponse].ADDR_ENTRY:
                    print(f"!!! Responder detected at: {answer.NB_ADDRESS} (NBNS -> {self.hostname})")
    
    def daemon(self):
        while True:
            self.send_llmnr_request()
            self.send_mdns_request()
            self.send_nbns_request()
            sleep(self.delay)

if __name__ == "__main__":
    print(respotter_ascii_logo)
    print("\nScanning for Responder...\n")
    
    parser = OptionParser()
    parser.add_option("-d", "--delay", dest="delay", help="Delay between scans in seconds", default=30)
    parser.add_option("-t", "--timeout", dest="timeout", help="Timeout for each scan in seconds", default=3)
    parser.add_option("-v", "--verbosity", dest="verbosity", help="Verbosity level (0-3)", default=0)
    parser.add_option("-n", "--hostname", dest="hostname", help="Hostname to scan for", default="Loremipsumdolorsitamet")
    (options, args) = parser.parse_args()

    respotter = Respotter(delay=int(options.delay),
                          hostname=options.hostname,
                          timeout=int(options.timeout),
                          verbosity=int(options.verbosity))
    
    respotter.daemon()