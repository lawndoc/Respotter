#!/usr/bin/env python3

from scapy.all import *
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, UDP
from scapy.layers.llmnr import LLMNRQuery, LLMNRResponse
from scapy.layers.netbios import NBNSQueryRequest, NBNSQueryResponse, NBNSHeader
from socket import *
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
                 timeout=3,
                 verbosity=0):
        self.delay = delay
        self.hostname = hostname
        self.timeout = timeout
        self.verbosity = verbosity
    
    def send_llmnr_request(self):
        # LLMNR uses the multicast IP 224.0.0.252 and UDP port 5355
        packet = IP(dst="224.0.0.252")/UDP(dport=5355)/LLMNRQuery(qd=DNSQR(qname=self.hostname))
        sniffer = AsyncSniffer(filter="udp dst port 5355", store=True)
        sniffer.start()
        sr1(packet, timeout=self.timeout, verbose=self.verbosity)
        time.sleep(self.timeout)
        response = sniffer.stop()
        if not response:
            return
        # Print all resolved IP addresses
        for sniffed_packet in response:
            if sniffed_packet.haslayer(LLMNRResponse):
                for i in range(sniffed_packet[LLMNRResponse].ancount):
                    if sniffed_packet[LLMNRResponse].an[i].type == 1:  # Type 1 is A record, which contains the IP address
                        print(f"!!! Responder detected at: {sniffed_packet[LLMNRResponse].an[i].rdata}")  # rdata field of the A record contains the IP address
        
    def send_mdns_request(self):
        # mDNS uses the multicast IP 224.0.0.251 and UDP port 5353
        packet = IP(dst="224.0.0.251")/UDP(dport=5353)/DNS(rd=1, qd=DNSQR(qname=self.hostname))
        sniffer = AsyncSniffer(filter="udp dst port 5353", store=True)
        sniffer.start()
        sr1(packet, timeout=self.timeout, verbose=self.verbosity)
        time.sleep(self.timeout)
        response = sniffer.stop()
        if not response:
            return
        # Print all resolved IP addresses
        for sniffed_packet in response:
            if sniffed_packet is not None and sniffed_packet.haslayer(DNS):
                for i in range(sniffed_packet[DNS].ancount):
                    if sniffed_packet[DNS].an[i].type == 1:
                        print(f"!!! Responder detected at: {sniffed_packet[DNS].an[i].rdata}")
        
    def send_nbns_request(self):
        # NBNS uses the broadcast IP 255.255.255.255 and UDP port 137
        packet = IP(dst="255.255.255.255")/UDP(sport=137, dport=137)/NBNSHeader(OPCODE=0x0, NM_FLAGS=0x11, QDCOUNT=1)/NBNSQueryRequest(SUFFIX="file server service", QUESTION_NAME=self.hostname, QUESTION_TYPE="NB")
        sniffer = AsyncSniffer(filter="udp dst port 137", store=True)
        sniffer.start()
        sr1(packet, timeout=self.timeout, verbose=self.verbosity)
        time.sleep(self.timeout)
        response = sniffer.stop()
        if not response:
            return
        # Print all resolved IP addresses
        for sniffed_packet in response:
            if sniffed_packet is not None and sniffed_packet.haslayer(NBNSQueryResponse):
                for i in range(sniffed_packet[NBNSQueryResponse].RDLENGTH):
                    print(f"!!! Responder detected at: {sniffed_packet[NBNSQueryResponse].ADDR_ENTRY[i].NB_ADDRESS}")
    
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