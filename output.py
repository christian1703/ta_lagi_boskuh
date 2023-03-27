#ooutputt.py

import sqlite3
import threading
import tkinter as tk
from tkinter import ttk, messagebox
from scapy.all import *
import datetime

# Create a window
window = tk.Tk()
window.title("Sniffing Detection")
window.geometry('800x600')

# Create a treeview to display the logs
tree = ttk.Treeview(window)
tree["columns"] = ("timestamp", "source_mac", "source_ip", "protocol", "payload")
tree.column("#0", width=0, stretch=tk.NO)
tree.column("timestamp", anchor=tk.CENTER, width=150)
tree.column("source_mac", anchor=tk.CENTER, width=150)
tree.column("source_ip", anchor=tk.CENTER, width=150)
tree.column("protocol", anchor=tk.CENTER, width=150)
tree.column("payload", anchor=tk.CENTER, width=300)
tree.heading("timestamp", text="Timestamp")
tree.heading("source_mac", text="Source MAC")
tree.heading("source_ip", text="Source IP")
tree.heading("protocol", text="Protocol")
tree.heading("payload", text="Payload")
tree.pack(fill=tk.BOTH, expand=1)

# Connect to database
conn = sqlite3.connect('log.db')
c = conn.cursor()

# Create a table to store logs if it doesn't exist
c.execute('''CREATE TABLE IF NOT EXISTS log
             (timestamp text, source_mac text, source_ip text, protocol text, payload text)''')

# Fetch all logs from the database
c.execute("SELECT * FROM log")
logs = c.fetchall()

# Insert the logs into the treeview
for log in logs:
    tree.insert("", tk.END, text=log[0], values=log[1:])

# Sniff function to detect sniffing
def sniff_packets(pkt):
    if pkt.haslayer(ICMP):
        print("PING Packet Detected")
        messagebox.showwarning("Sniffing Alert", "PING Packet Detected!")
        
    elif pkt.haslayer(DNS):
        print("DNS Packet Detected")
        messagebox.showwarning("Sniffing Alert", "DNS Packet Detected!")

    elif pkt.haslayer(ARP):
        print("ARP Packet Detected")
        messagebox.showwarning("Sniffing Alert", "ARP Packet Detected!")

    # Insert the sniffed packet into the treeview
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    source_mac = pkt.src
    source_ip = pkt[IP].src
    protocol = pkt.summary()
    payload = str(pkt.payload)

    tree.insert("", tk.END, text=timestamp, values=(timestamp, source_mac, source_ip, protocol, payload))

    # Insert the sniffed packet into the database
    c.execute("INSERT INTO log (timestamp, source_mac, source_ip, protocol, payload) VALUES (?, ?, ?, ?, ?)", (timestamp, source_mac, source_ip, protocol, payload))
    conn.commit()


# Start sniffing packets on a separate thread
def start_sniffing():
    sniff(prn=sniff_packets)

threading.Thread(target=start_sniffing, daemon=True).start()

# Start the GUI event loop
window.mainloop()

# Close the database connection when the application is closed
conn.close()