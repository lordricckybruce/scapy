#!/bin/python3
'''
can create packet,
decode and analyze network traffic,
perform network discovery and security tests
'''
from scapy.all import IP, ICMP, TCP, sr1, send, sniff

# Step 1: Construct a custom packet
packet = IP(dst="8.8.8.8", ttl=64)/ICMP()/"Hello from Scapy!"
#ICMP adds icmp protocol layer, ttl=64 sets the "TIME TO LIVE" field, controlling how many hops the packet can traverse.
#dst is target destination
# hello from scappy appends custom payload data
print("[*] Custom Packet Created:")
print(packet.show())  #to detail structure of the packet

# Step 2: Send the packet and capture a single response
print("\n[*] Sending the packet...")
response = sr1(packet, timeout=2)
# srl sends packet and wait for signal
#timeout waits for 2seconds
#response handling: if response is received, it prints summary, otherwise it reports no response
if response:
    print("[*] Received response:")
    print(response.summary())
else:
    print("[*] No response received.")

# Step 3: Sniff network traffic and filter for TCP packets
print("\n[*] Starting packet sniffing... (Ctrl+C to stop)")
def process_packet(pkt):
    if TCP in pkt:
        print(f"[*] Sniffed TCP Packet: {pkt[IP].src} -> {pkt[IP].dst}")
        pkt.show()

# Sniff packets, filter by TCP, and use process_packet as the callback
sniff(filter="tcp", prn=process_packet, count=5)

#sniff captures packets from network while filter=tcp caputres only tcp packets using Berkeley Packet Filter (BPF) syntax
#prn=process_packetcalls back function
#count5 Stops capturing 5 packets
#pkt.show() shows more detailed information
'''
Advantages:
Customizable
interactive

'''
