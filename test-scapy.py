from scapy.all import *
from scapy.layers.inet import IP

def chgSend(pckt):
    
    try:
        t = pckt[IP].src
    except IndexError:
        return

    pckt[IP].dst = '192.168.1.69'

    try:
        send(pckt)
    except OSError:
        return

    #print(actual_src)
    #pckt[IP].src = "192.168.1.5"
    #pckt[IP].tos = 1
    #sendp(pckt)
    #print("We changed source from " + actual_src + " to " + pckt[IP].src)

try:
    sniff(iface="wlp3s0", prn=chgSend)
except KeyboardInterrupt:
    exit(0)
