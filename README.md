# Advanced Packet Sniffer + ARP Spoofing Detector

## Overview

This project is a Python-based network monitoring tool developed using the Scapy library. It captures network packets in real time, identifies protocols, analyzes source and destination IP addresses, and detects potential ARP spoofing attacks by monitoring IP-to-MAC address mappings.

## Features

* Real-time packet capture
* TCP, UDP, and ICMP protocol detection
* Source and destination IP analysis
* Port number monitoring
* ARP traffic monitoring
* ARP spoofing detection
* Packet statistics summary

## Technologies Used

* Python
* Scapy

## How to Run

### Install Dependencies

```bash
pip install -r requirements.txt
```

### Run the Program

```bash
python advanced_sniffer.py
```

## Sample Output

```text
[16:10:34] TCP: 192.168.1.17:26383 -> 148.113.20.3:443
[16:10:34] TCP: 148.113.20.3:443 -> 192.168.1.17:26383

[ARP] Learned: 192.168.1.1 -> 64:fb:92:46:c6:82
```

## Learning Outcomes

* Network packet analysis
* TCP/IP protocol understanding
* ARP protocol monitoring
* Basic threat detection concepts
* Python scripting for cybersecurity


