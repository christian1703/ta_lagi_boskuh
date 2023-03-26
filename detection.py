# detection.py

import logging
import sqlite3
from datetime import datetime
from scapy.all import *

# Set up logging configuration
logging.basicConfig(filename='logs.log', level=logging.DEBUG)

# Connect to database
conn = sqlite3.connect('log.db')
c = conn.cursor()

# Create table if it doesn't exist
c.execute('''CREATE TABLE IF NOT EXISTS log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                source_mac TEXT,
                source_ip TEXT,
                protocol TEXT,
                payload TEXT
            )''')
conn.commit()
# Define a function to insert log into database
def insert_log(pkt):
    if IP not in pkt:
        return

    if pkt.haslayer(ICMP) and pkt[ICMP].type == 8:
        protocol = 'Ping'
        payload = f"Source:{pkt[Ether].src} ({pkt[IP].src})"
    elif pkt.haslayer(DNSQR):
        protocol = 'DNS Query'
        payload = f"Source:{pkt[Ether].src} ({pkt[IP].src}) for: {pkt[DNSQR].qname.decode()}"
    elif pkt.haslayer(ARP):
        protocol = 'ARP Request'
        payload = f"Source:{pkt[Ether].src} ({pkt[ARP].psrc}) for: {pkt[ARP].pdst}"
    else:
        return

    timestamp = str(datetime.now())
    source_mac = pkt[Ether].src
    source_ip = pkt[IP].src

    # Insert log into database
    c.execute("INSERT INTO log (timestamp, source_mac, source_ip, protocol, payload) VALUES (?, ?, ?, ?, ?)", (timestamp, source_mac, source_ip, protocol, payload))
    conn.commit()

    # Check for sniffing
    c.execute("SELECT source_mac, source_ip FROM log WHERE protocol=? AND timestamp > datetime('now', '-10 seconds')", (protocol,))
    logs = c.fetchall()
    if len(logs) > 1:
        for log in logs[:-1]:
            if log[0] != source_mac or log[1] != source_ip:
                logging.warning("%s Sniffing detected from : %s (%s)", timestamp, source_mac, source_ip)
                break
#Start capturing packets and analyzing them 
sniff(filter="icmp or udp port 53 or arp", prn=insert_log)