#!/usr/bin/env python3

from scapy.all import *
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, UDP
from scapy.layers.llmnr import LLMNRQuery, LLMNRResponse
from scapy.layers.netbios import NBNSQueryRequest, NBNSQueryResponse, NBNSHeader
from time import sleep

respotter_ascii_logo = """\
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
                 timeout=3,
                 verbosity=0):
        self.delay = delay
        self.hostname = hostname
        self.timeout = timeout
        self.verbosity = verbosity
    
    def send_llmnr_request(self):
        # LLMNR uses the multicast IP 224.0.0.252 and UDP port 5355
        packet = IP(dst="224.0.0.252")/UDP(dport=5355)/LLMNRQuery(qd=DNSQR(qname=self.hostname))
        response = sr1(packet, timeout=self.timeout, verbose=self.verbosity)
        if response is not None and response.haslayer(LLMNRResponse):
            # Print all resolved IP addresses
            for i in range(response[LLMNRResponse].ancount):
                if response[LLMNRResponse].an[i].type == 1:  # Type 1 is A record, which contains the IP address
                    print(f"!!! Responder detected at: {response[LLMNRResponse].an[i].rdata}")  # rdata field of the A record contains the IP address
        
    def send_mdns_request(self):
        # mDNS uses the multicast IP 224.0.0.251 and UDP port 5353
        packet = IP(dst="224.0.0.251")/UDP(dport=5353)/DNS(rd=1, qd=DNSQR(qname=self.hostname))
        response = sr1(packet, timeout=self.timeout, verbose=self.verbosity)
        if response is not None and response.haslayer(DNS):
            # Print all resolved IP addresses
            for i in range(response[DNS].ancount):
                if response[DNS].an[i].type == 1:
                    print(f"!!! Responder detected at: {response[DNS].an[i].rdata}")
        
    def send_nbns_request(self):
        # NBNS uses the broadcast IP 255.255.255.255 and UDP port 137
        packet = IP(dst="255.255.255.255")/UDP(sport=137, dport=137)/NBNSHeader(OPCODE=0x0, NM_FLAGS=0x11, QDCOUNT=1)/NBNSQueryRequest(SUFFIX="file server service", QUESTION_NAME=self.hostname, QUESTION_TYPE="NB")
        response = sr1(packet, timeout=self.timeout, verbose=self.verbosity)
        if response is not None and response.haslayer(NBNSQueryResponse):
            # Print all resolved IP addresses
            for i in range(response[NBNSQueryResponse].RDLENGTH):
                print(f"!!! Responder detected at: {response[NBNSQueryResponse].ADDR_ENTRY[i].NB_ADDRESS}")
    
    def daemon(self):
        while True:
            self.send_llmnr_request()
            self.send_mdns_request()
            self.send_nbns_request()
            sleep(self.delay)

if __name__ == "__main__":
    print(respotter_ascii_logo)
    print("\nScanning for Responder...\n")
    respotter = Respotter(delay=3)
    respotter.daemon()