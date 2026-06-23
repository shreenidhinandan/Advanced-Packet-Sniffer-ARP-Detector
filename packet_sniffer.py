from scapy.all import sniff, IP, TCP, UDP, ICMP

def packet_callback(packet):

    if packet.haslayer(IP):

        src = packet[IP].src
        dst = packet[IP].dst

        if packet.haslayer(TCP):
            protocol = "TCP"
        elif packet.haslayer(UDP):
            protocol = "UDP"
        elif packet.haslayer(ICMP):
            protocol = "ICMP"
        else:
            protocol = "Other"

        print(f"{protocol}: {src} -> {dst}")

sniff(prn=packet_callback, store=False)