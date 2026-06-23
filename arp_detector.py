from scapy.all import *

arp_table = {}

def detect_arp(packet):

    if packet.haslayer(ARP):

        ip = packet[ARP].psrc
        mac = packet[ARP].hwsrc

        print(f"IP: {ip}  MAC: {mac}")

        if ip in arp_table:

            if arp_table[ip] != mac:

                print("\n[ALERT] Possible ARP Spoofing Detected!")
                print(f"IP: {ip}")
                print(f"Old MAC: {arp_table[ip]}")
                print(f"New MAC: {mac}")

        else:
            arp_table[ip] = mac
            print(f"Learned: {ip} -> {mac}")

print("Monitoring ARP Traffic...")
sniff(filter="arp", prn=detect_arp, store=False)