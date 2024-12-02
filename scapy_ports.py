#!/bin/python3

#after network discovery is port scanning

from scapy.all import IP, TCP, sr1

def scan_ports(target, ports):
    for port in ports:
        # Create the SYN packet
        packet = IP(dst=target)/TCP(dport=port, flags="S")
	#/TCP(dport , flags="S") appends a TCP packet with dport -- detsination port , flag sets the syn flag 
        # Send the packet and wait for a response
        response = sr1(packet, timeout=1, verbose=False)

        if response:  # to check for recieved response
		#haslayer--check if response contained in tcp layer
		#getlayer--checks tcp flags in response
		#0x12 is the hexadecimal value and for succesful connection, 0x14 RST-ACK Reset-ACK for closed ports
            if response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
                print(f"Port {port} is open.")
            elif response.haslayer(TCP) and response.getlayer(TCP).flags == 0x14:
                print(f"Port {port} is closed.")
        else:
            print(f"Port {port} is filtered (no response).")

# Call the function to scan ports 22, 80, and 443 on the target system
scan_ports("192.168.1.1", [22, 80, 443])

'''
Advantages
stealthy
disadvantage
o.y.o -- on your own if them catch you (lol!!!!!!!)
'''
