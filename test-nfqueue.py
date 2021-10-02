#!/usr/bin/env python

from netfilterqueue import NetfilterQueue
from scapy.layers.inet import IP
from scapy.all import *

def process_packet(packet):
    pckt = IP(packet.get_payload())
    ip = pckt.sprintf("{IP:%IP.src%}")
    data = pckt.sprintf("{Raw:%Raw.load%}")

    #print(ip)
    #f data.find("HTTP") != -1:
    #    print(data)

    if data[:4] == "'GET" and data.find("Referer") == -1:
        arr = data.split("\\r\\n")
        arr2 = arr[1].split(" ")
        print(f"'{ip}' visited '{arr2[1]}'")

    packet.accept()

queue = NetfilterQueue()
queue.bind(0, process_packet)
try:
    queue.run()
except KeyboardInterrupt:
    print('')
