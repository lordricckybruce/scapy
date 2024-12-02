#!/bin/python3
'''
Netdiscovery with ping sweep, a simple technique for discovering all active 
hostby sending icmp echo request to a range of ip addresses, if the host 
is alive oiit respond with echo reply.
'''

from scapy.all import IP, ICMP, sr1
#IP --  Scapy class for creating and manipulating IP packets and aloow to define source and destinantion ip address
#ICMP -- a class for creating and sending ICMP packets , which are used for sending error messages
#sr1 --  for sending a sngle packets and wait fpr response
def ping_sweep(network):     #defining ping_sweep
    # Define the network range to scan (e.g., 192.168.1.0/24)
    for ip in range(1, 255):
        # Create an IP packet with ICMP
        target_ip = f"{network}.{ip}"
        packet = IP(dst=target_ip)/ICMP()  # Create the ICMP packet
	#creating the icmp packet, ip with dst(destination) and target ip
	#icmp creates the echo request i.e you are creating a packet that ask target device 'Are you there".
        response = sr1(packet, timeout=1, verbose=False)  # Send packet and wait for repl
	#sr1 sends packets and wait, time out of 1sec, verbose=false--ensures scapy won't printout too much information
        if response:
            print(f"Host {target_ip} is alive.")
        else:
            print(f"Host {target_ip} is down.")

# Call the function to perform a ping sweep
ping_sweep("192.168.1")

