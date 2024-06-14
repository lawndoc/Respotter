#!/usr/bin/env python3

from scapy.all import *
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, UDP
from scapy.layers.llmnr import LLMNRQuery, LLMNRResponse
from scapy.layers.netbios import NBNSQueryRequest, NBNSQueryResponse
from time import sleep

class Respotter:
    def __init__(self, delay=30, hostname="Loremipsumdolorsitamet"):
        self.delay = delay
        self.hostname = hostname
    
    def send_llmnr_request(self):
        # LLMNR uses the multicast IP 224.0.0.252 and UDP port 5355
        packet = IP(dst="224.0.0.252")/UDP(dport=5355)/LLMNRQuery(qd=DNSQR(qname=self.hostname))
        response = sr1(packet, timeout=3, verbose=1)
        if response is not None and response.haslayer(DNS):
            # Print all resolved IP addresses
            for i in range(response[LLMNRResponse].ancount):
                if response[LLMNRResponse].an[i].type == 1:  # Type 1 is A record, which contains the IP address
                    print(f"!!! Responder detected at: {response[LLMNRResponse].an[i].rdata}")  # rdata field of the A record contains the IP address
        
    def send_mdns_request(self):
        # mDNS uses the multicast IP 224.0.0.251 and UDP port 5353
        packet = IP(dst="224.0.0.251")/UDP(dport=5353)/DNS(rd=1, qd=DNSQR(qname=self.hostname))
        response = sr1(packet, timeout=3, verbose=1)
        if response is not None and response.haslayer(DNS):
            # Print all resolved IP addresses
            for i in range(response[DNS].ancount):
                if response[DNS].an[i].type == 1:
                    print(f"!!! Responder detected at: {response[DNS].an[i].rdata}")
        
    def send_nbns_request(self):
        # NBNS uses the broadcast IP 255.255.255.255 and UDP port 137
        packet = IP(dst="255.255.255.255")/UDP(dport=137)/NBNSQueryRequest(QUESTION_NAME=self.hostname)
        response = sr1(packet, timeout=3, verbose=1)
        if response is not None and response.haslayer(NBNSQueryResponse):
            # Print all resolved IP addresses
            for i in range(response[NBNSQueryResponse].ancount):
                if response[NBNSQueryResponse].an[i].TYPE == 1:
                    print(f"!!! Responder detected at: {response[NBNSQueryResponse].an[i].rdata}")
    
    def run(self):
        while True:
            self.send_llmnr_request()
            self.send_mdns_request()
            self.send_nbns_request()
            sleep(self.delay)

if __name__ == "__main__":
    respotter = Respotter(delay=3)
    respotter.run()