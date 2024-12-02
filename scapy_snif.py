#!/bin/python3


#capture live traffic on network to analyze protocols, headres and data

from scapy.all import sniff

def packet_callback(packet):
    print(packet.show())  # Display packet details

# Sniff TCP packets
sniff(filter="tcp", prn=packet_callback, count=10)  # Capture 10 packets

#filter="tcp" limits to capture tcp packets
#prn=packet_callback for each captured packet
