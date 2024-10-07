import tkinter as tk
from tkinter import ttk
from tkinter import scrolledtext
from PIL import Image, ImageTk
import os
import sys
from drop import user_ipv4
import pandas as pd
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP


# Replace with your laptop's IP address
YOUR_IP_ADDRESS = user_ipv4

packet_list = []
malformed_packets = []
malicious_packets = []

known_malicious_patterns = [
    ("192.168.1.100", "192.168.1.1", 12345, 80),
    ("10.0.0.5", "10.0.0.1", 54321, 443),
    ("172.16.0.2", "172.16.0.1", 8080, 22),
    ("203.0.113.5", "192.0.2.1", 22, 22),
    ("198.51.100.7", "198.51.100.3", 80, 8080),
    ("198.51.100.7", "198.51.100.3", 4444, 22),
    ("192.168.1.105", "192.168.1.50", 0, 445),
("192.168.1.100", "192.168.1.1", 12345, 80),
    ("10.0.0.5", "10.0.0.1", 54321, 443),
    ("172.16.0.2", "172.16.0.1", 8080, 22),
    ("203.0.113.5", "192.0.2.1", 22, 22),
    ("198.51.100.7", "198.51.100.3", 80, 8080),
    ("198.51.100.7", "198.51.100.3", 4444, 22),
    ("192.168.1.105", "192.168.1.50", 0, 445),
    ("192.168.1.200", "192.168.1.2", 12346, 80),
    ("10.0.0.10", "10.0.0.2", 54322, 443),
    ("172.16.0.3", "172.16.0.4", 8081, 22),
    ("203.0.113.6", "192.0.2.2", 23, 22),
    ("198.51.100.8", "198.51.100.4", 81, 8081),
    ("198.51.100.9", "198.51.100.5", 4445, 23),
    ("192.168.1.106", "192.168.1.51", 1, 445),
    ("192.168.1.101", "192.168.1.3", 12347, 80),
    ("10.0.0.6", "10.0.0.3", 54323, 443),
    ("172.16.0.4", "172.16.0.5", 8082, 22),
    ("203.0.113.7", "192.0.2.3", 24, 22),
    ("198.51.100.10", "198.51.100.6", 82, 8082),
    ("198.51.100.11", "198.51.100.7", 4446, 24),
    ("192.168.1.107", "192.168.1.52", 2, 445),
    ("192.168.1.102", "192.168.1.4", 12348, 80),
    ("10.0.0.7", "10.0.0.4", 54324, 443),
    ("172.16.0.5", "172.16.0.6", 8083, 22),
    ("203.0.113.8", "192.0.2.4", 25, 22),
    ("198.51.100.12", "198.51.100.8", 83, 8083),
    ("198.51.100.13", "198.51.100.9", 4447, 25),
    ("192.168.1.108", "192.168.1.53", 3, 445),
    ("192.168.1.103", "192.168.1.5", 12349, 80),
    ("10.0.0.8", "10.0.0.5", 54325, 443),
    ("172.16.0.6", "172.16.0.7", 8084, 22),
    ("203.0.113.9", "192.0.2.5", 26, 22),
    ("198.51.100.14", "198.51.100.10", 84, 8084),
    ("198.51.100.15", "198.51.100.11", 4448, 26),
    ("192.168.1.109", "192.168.1.54", 4, 445),
    ("192.168.1.104", "192.168.1.6", 12350, 80),
    ("10.0.0.9", "10.0.0.6", 54326, 443),
    ("172.16.0.7", "172.16.0.8", 8085, 22),
    ("203.0.113.10", "192.0.2.6", 27, 22),
    ("198.51.100.16", "198.51.100.12", 85, 8085),
    ("198.51.100.17", "198.51.100.13", 4449, 27),
    ("192.168.1.110", "192.168.1.55", 5, 445),
    ("192.168.1.105", "192.168.1.7", 12351, 80),
    ("10.0.0.10", "10.0.0.7", 54327, 443),
    ("172.16.0.8", "172.16.0.9", 8086, 22),
    ("203.0.113.11", "192.0.2.7", 28, 22),
    ("198.51.100.18", "198.51.100.14", 86, 8086),
    ("198.51.100.19", "198.51.100.15", 4450, 28),
    ("192.168.1.111", "192.168.1.56", 6, 445),
    ("192.168.1.106", "192.168.1.8", 12352, 80),
    ("10.0.0.11", "10.0.0.8", 54328, 443),
    ("172.16.0.9", "172.16.0.10", 8087, 22),
    ("203.0.113.12", "192.0.2.8", 29, 22),
    ("198.51.100.20", "198.51.100.16", 87, 8087),
    ("198.51.100.21", "198.51.100.17", 4451, 29),
    ("192.168.1.112", "192.168.1.57", 7, 445),
    ("192.168.1.107", "192.168.1.9", 12353, 80),
    ("10.0.0.12", "10.0.0.9", 54329, 443),
    ("172.16.0.10", "172.16.0.11", 8088, 22),
    ("203.0.113.13", "192.0.2.9", 30, 22),
    ("198.51.100.22", "198.51.100.18", 88, 8088),
    ("198.51.100.23", "198.51.100.19", 4452, 30),
    ("192.168.1.113", "192.168.1.58", 8, 445),
    ("192.168.1.108", "192.168.1.10", 12354, 80),
    ("10.0.0.13", "10.0.0.10", 54330, 443),
    ("172.16.0.11", "172.16.0.12", 8089, 22),
    ("203.0.113.14", "192.0.2.10", 31, 22),
    ("198.51.100.24", "198.51.100.20", 89, 8089),
    ("198.51.100.25", "198.51.100.21", 4453, 31),
    ("192.168.1.114", "192.168.1.59", 9, 445),
    ("192.168.1.109", "192.168.1.11", 12355, 80),
    ("203.0.113.15", "192.0.2.11", 32, 22),
    ("198.51.100.26", "198.51.100.22", 90, 8090),
    ("198.51.100.27", "198.51.100.23", 4454, 32),
    ("192.168.1.115", "192.168.1.60", 10, 445),
    ("192.168.1.110", "192.168.1.12", 12356, 80),
    ("10.0.0.15", "10.0.0.12", 54332, 443),
    ("172.16.0.13", "172.16.0.14", 8091, 22),
    ("203.0.113.16", "192.0.2.12", 33, 22),
    ("198.51.100.28", "198.51.100.24", 91, 8091),
    ("198.51.100.29", "198.51.100.25", 4455, 33),
    ("192.168.1.116", "192.168.1.61", 11, 445),
    ("192.168.1.111", "192.168.1.13", 12357, 80),
    ("10.0.0.16", "10.0.0.13", 54333, 443),
    ("172.16.0.14", "172.16.0.15", 8092, 22),
    ("203.0.113.17", "192.0.2.13", 34, 22),
    ("198.51.100.30", "198.51.100.26", 92, 8092),
    ("198.51.100.31", "198.51.100.27", 4456, 34),
    ("192.168.1.117", "192.168.1.62", 12, 445),
    ("192.168.1.112", "192.168.1.14", 12358, 80),
    ("10.0.0.17", "10.0.0.14", 54334, 443),
    ("172.16.0.15", "172.16.0.16", 8093, 22),
    ("203.0.113.18", "192.0.2.14", 35, 22),
    ("198.51.100.32", "198.51.100.28", 93, 8093),
    ("198.51.100.33", "198.51.100.29", 4457, 35),
    ("192.168.1.118", "192.168.1.63", 13, 445),
    ("192.168.1.113", "192.168.1.15", 12359, 80),
    ("10.0.0.18", "10.0.0.15", 54335, 443),
    ("172.16.0.16", "172.16.0.17", 8094, 22),
    ("203.0.113.19", "192.0.2.15", 36, 22),
    ("198.51.100.34", "198.51.100.30", 94, 8094),
    ("198.51.100.35", "198.51.100.31", 4458, 36),
    ("192.168.1.119", "192.168.1.64", 14, 445),
    ("192.168.1.114", "192.168.1.16", 12360, 80),
    ("10.0.0.19", "10.0.0.16", 54336, 443),
    ("172.16.0.17", "172.16.0.18", 8095, 22),
    ("203.0.113.20", "192.0.2.16", 37, 22),
    ("198.51.100.36", "198.51.100.32", 95, 8095),
    ("198.51.100.37", "198.51.100.33", 4459, 37),
    ("192.168.1.120", "192.168.1.65", 15, 445),
    ("192.168.1.115", "192.168.1.17", 12361, 80),
    ("10.0.0.20", "10.0.0.17", 54337, 443),
    ("172.16.0.18", "172.16.0.19", 8096, 22),
    ("203.0.113.21", "192.0.2.17", 38, 22),
    ("198.51.100.38", "198.51.100.34", 96, 8096),
    ("198.51.100.39", "198.51.100.35", 4460, 38),
    ("192.168.1.121", "192.168.1.66", 16, 445),
    ("192.168.1.116", "192.168.1.18", 12362, 80),
    ("10.0.0.21", "10.0.0.18", 54338, 443),
    ("172.16.0.19", "172.16.0.20", 8097, 22),
    ("203.0.113.22", "192.0.2.18", 39, 22),
    ("198.51.100.40", "198.51.100.36", 97, 8097),
    ("198.51.100.41", "198.51.100.37", 4461, 39),
    ("192.168.1.122", "192.168.1.67", 17, 445),
    ("192.168.1.117", "192.168.1.19", 12363, 80),
    ("10.0.0.22", "10.0.0.19", 54339, 443),
    ("172.16.0.20", "172.16.0.21", 8098, 22),
    ("203.0.113.23", "192.0.2.19", 40, 22),
    ("198.51.100.42", "198.51.100.38", 98, 8098),
    ("198.51.100.43", "198.51.100.39", 4462, 40),
    ("192.168.1.123", "192.168.1.68", 18, 445),
    ("192.168.1.118", "192.168.1.20", 12364, 80),
    ("10.0.0.23", "10.0.0.20", 54340, 443),
    ("172.16.0.21", "172.16.0.22", 8099, 22),
    ("203.0.113.24", "192.0.2.20", 41, 22),
    ("198.51.100.44", "198.51.100.40", 99, 8099),
    ("198.51.100.45", "198.51.100.41", 4463, 41),
    ("192.168.1.124", "192.168.1.69", 19, 445),
    ("192.168.1.119", "192.168.1.21", 12365, 80),
    ("10.0.0.24", "10.0.0.21", 54341, 443),
    ("172.16.0.22", "172.16.0.23", 8100, 22),
    ("203.0.113.25", "192.0.2.21", 42, 22),
    ("198.51.100.46", "198.51.100.42", 100, 8100),
    ("198.51.100.47", "198.51.100.43", 4464, 42)
]


def detect_malformed_packet(packet):
    if IP in packet:
        if TCP in packet or UDP in packet:
            if len(packet[IP]) < packet[IP].ihl * 4:
                return True
    return False


def detect_malicious_patterns(packet):
    if IP in packet:
        # Only check patterns if the packet's source or destination IP matches your IP
        if packet[IP].src == YOUR_IP_ADDRESS or packet[IP].dst == YOUR_IP_ADDRESS:
            for pattern in known_malicious_patterns:
                src_ip, dst_ip, src_port, dst_port = pattern
                if packet[IP].src == src_ip and packet[IP].dst == dst_ip:
                    if TCP in packet and packet[TCP].sport == src_port and packet[TCP].dport == dst_port:
                        return True
    return False


def packet_callback(packet):
    if IP in packet:
        packet_info = {
            "ip_src": packet[IP].src,
            "ip_dst": packet[IP].dst,
            "proto": packet[IP].proto
        }
        if TCP in packet:
            packet_info.update({
                "sport": packet[TCP].sport,
                "dport": packet[TCP].dport,
                "flags": packet[TCP].flags
            })
        elif UDP in packet:
            packet_info.update({
                "sport": packet[UDP].sport,
                "dport": packet[UDP].dport
            })
        packet_list.append(packet_info)

        if detect_malformed_packet(packet):
            malformed_packets.append(packet)

        if detect_malicious_patterns(packet):
            malicious_packets.append(packet)


# Capture packets and process them
sniff(prn=packet_callback, store=0, count=60)

# Convert captured packet data to a DataFrame
df = pd.DataFrame(packet_list)

# Check for unique destination ports contacted by each source IP (port scan detection)
port_scan_threshold = 10
suspected_scanners = df.groupby('ip_src')['dport'].nunique()
suspected_scanners = suspected_scanners[suspected_scanners > port_scan_threshold]

# Print results
print("Suspected Port Scanners:")
print(suspected_scanners)
print(f"Number of malformed packets detected: {len(malformed_packets)}")
print(f"Number of malicious packets detected: {len(malicious_packets)}")

with open("emailing.py") as f:
    code = f.read()
    exec(code)

# Create the main window
root = tk.Tk()
root.title("Anomaly Detector")

# Set the dimensions and position of the window
window_width = 700
window_height = 700
screen_width = root.winfo_screenwidth()
screen_height = root.winfo_screenheight()
position_top = int(screen_height / 2 - window_height / 2)
position_right = int(screen_width / 2 - window_width / 2)
root.geometry(f'{window_width}x{window_height}+{position_right}+{position_top}')

# Create a canvas
canvas = tk.Canvas(root, width=window_width, height=window_height)
canvas.pack(fill="both", expand=True)
bg_image = None
# Function to load and resize the background image
def load_background_image():
    global bg_image
    background_image = Image.open(r"C:/Users/USER/Pictures/des.jpg")
    background_image = background_image.resize((root.winfo_width(), root.winfo_height()))
    bg_image = ImageTk.PhotoImage(background_image)
    canvas.create_image(0, 0, anchor=tk.NW, image=bg_image)
frame = ttk.Frame(canvas)
frame.place(relx=0.5, rely=0.5, anchor=tk.CENTER)

# Create a ScrolledText widget to display packet information
text_area = scrolledtext.ScrolledText(frame, wrap=tk.WORD, height=20, width=80)
text_area.pack(expand=True, fill='both')

def insert_text(output):
    text_area.insert(tk.END, output + '\n')
    text_area.see(tk.END)

# Bind the resize event to update the background image
def on_resize(event):
    load_background_image()
insert_text('Network Monitoring Started...')
insert_text("Monitor it through the App's Description.")
root.bind('<Configure>', on_resize)



root.mainloop()



