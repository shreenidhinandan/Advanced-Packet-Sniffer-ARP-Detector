from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP
from datetime import datetime

# ARP table for spoofing detection
arp_table = {}

# Packet counters
packet_count = 0
tcp_count = 0
udp_count = 0
icmp_count = 0


def packet_callback(packet):
    global packet_count, tcp_count, udp_count, icmp_count

    packet_count += 1
    timestamp = datetime.now().strftime("%H:%M:%S")

    # -----------------------------
    # IP Packet Analysis
    # -----------------------------
    if packet.haslayer(IP):

        src = packet[IP].src
        dst = packet[IP].dst

        if packet.haslayer(TCP):
            tcp_count += 1

            print(
                f"[{timestamp}] TCP: "
                f"{src}:{packet[TCP].sport} -> "
                f"{dst}:{packet[TCP].dport}"
            )

        elif packet.haslayer(UDP):
            udp_count += 1

            print(
                f"[{timestamp}] UDP: "
                f"{src}:{packet[UDP].sport} -> "
                f"{dst}:{packet[UDP].dport}"
            )

        elif packet.haslayer(ICMP):
            icmp_count += 1

            print(
                f"[{timestamp}] ICMP: "
                f"{src} -> {dst}"
            )

        else:
            print(
                f"[{timestamp}] OTHER: "
                f"{src} -> {dst}"
            )

    # -----------------------------
    # ARP Spoofing Detection
    # -----------------------------
    if packet.haslayer(ARP):

        ip = packet[ARP].psrc
        mac = packet[ARP].hwsrc

        # Learn new ARP mapping
        if ip not in arp_table:
            arp_table[ip] = mac
            print(f"[ARP] Learned: {ip} -> {mac}")

        # Detect MAC change
        elif arp_table[ip] != mac:

            print("\n" + "=" * 60)
            print("[ALERT] POSSIBLE ARP SPOOFING DETECTED!")
            print(f"IP Address : {ip}")
            print(f"Old MAC    : {arp_table[ip]}")
            print(f"New MAC    : {mac}")
            print("=" * 60 + "\n")


print("==========================================")
print(" Advanced Packet Sniffer + ARP Detector")
print("==========================================")
print("Press Ctrl + C to stop...\n")

try:
    sniff(prn=packet_callback, store=False)

except KeyboardInterrupt:

    print("\n\n========== SUMMARY ==========")
    print(f"Total Packets : {packet_count}")
    print(f"TCP Packets   : {tcp_count}")
    print(f"UDP Packets   : {udp_count}")
    print(f"ICMP Packets  : {icmp_count}")
    print("=============================")