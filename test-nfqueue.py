#!/usr/bin/env python
from netfilterqueue import NetfilterQueue
 
def process_packet(packet):
    print(packet)
    packet.accept()
 
queue = NetfilterQueue()
queue.bind(1, process_packet)
try:
    queue.run()
except KeyboardInterrupt:
    print('')

# https://www.shuzhiduo.com/R/VGzl4oW1zb/