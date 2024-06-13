#!/usr/bin/env python3

import json
from scapy.all import *
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, UDP
from time import sleep

class Respotter:
    def __init__(self, delay=30, hostname="Loremipsumdolorsitamet"):
        self.delay = delay
        self.hostname = hostname
    
    def send_llmnr_request(self):
        # LLMNR uses the multicast IP 224.0.0.252 and UDP port 5355
        packet = IP(dst="224.0.0.252")/UDP(dport=5355)/DNS(rd=1, qd=DNSQR(qname=self.hostname))
        send(packet)
    
    def run(self):
        while True:
            self.send_llmnr_request()
            sleep(self.delay)

if __name__ == "__main__":
    respotter = Respotter(delay=3)
    respotter.run()