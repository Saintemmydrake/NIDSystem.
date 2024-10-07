import tkinter as tk
from tkinter import scrolledtext, filedialog
from scapy.all import sniff
from scapy.layers.inet import TCP, IP
import threading
from PIL import Image, ImageTk

class PacketAnalyzerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Traffic Analyzer")

        # Set window size
        self.window_width = 700
        self.window_height = 700

        # Get screen width and height
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()

        # Calculate position to center the window
        x = (screen_width - self.window_width) // 2
        y = (screen_height - self.window_height) // 2

        # Set window size and position
        self.root.geometry(f'{self.window_width}x{self.window_height}+{x}+{y}')

        # Create a canvas for the background image
        self.canvas = tk.Canvas(root, width=self.window_width, height=self.window_height)
        self.canvas.pack(fill="both", expand=True)

        # Load the background image
        background_image = Image.open(r"C:/Users/USER/Pictures/des.jpg")  # Use a valid path
        background_image = background_image.resize((self.window_width, self.window_height))
        self.bg_image = ImageTk.PhotoImage(background_image)

        # Set the background image on the canvas
        self.canvas.create_image(0, 0, anchor=tk.NW, image=self.bg_image)

        # Create a ScrolledText widget to display packet information
        self.text_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, height=20, width=80)
        self.text_area.place(relx=0.5, rely=0.5, anchor=tk.CENTER)

        # Create buttons for Start, Stop, Save, and Save As
        self.start_button = tk.Button(root, text="Start", command=self.start_sniffing)
        self.start_button.place(relx=0.1, rely=0.9, anchor=tk.S)

        self.stop_button = tk.Button(root, text="Stop", command=self.stop_sniffing, state=tk.DISABLED)
        self.stop_button.place(relx=0.2, rely=0.9, anchor=tk.S)

        self.save_button = tk.Button(root, text="Save", command=self.save_file, state=tk.DISABLED)
        self.save_button.place(relx=0.3, rely=0.9, anchor=tk.S)

        self.save_as_button = tk.Button(root, text="Save As", command=self.save_as_file, state=tk.DISABLED)
        self.save_as_button.place(relx=0.4, rely=0.9, anchor=tk.S)

        self.sniff_thread = None
        self.sniffing = False
        self.packet_data = []

    def packet_callback(self, packet):
        if packet.haslayer(IP):
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            proto = packet[IP].proto
            packet_size = len(packet)
            packet_info = f'IP {ip_src} -> {ip_dst}, Protocol: {proto}, Size: {packet_size} bytes\n'

            if packet.haslayer(TCP):
                tcp_sport = packet[TCP].sport
                tcp_dport = packet[TCP].dport
                tcp_flags = packet[TCP].flags
                tcp_info = f'    TCP {ip_src}:{tcp_sport} -> {ip_dst}:{tcp_dport}, Flags: {tcp_flags}\n'
                packet_info += tcp_info

            # Store packet information and update the text area in the GUI
            self.root.after(0, self.update_text_area, packet_info)

    def update_text_area(self, packet_info):
        self.text_area.insert(tk.END, packet_info)
        self.text_area.yview(tk.END)

    def start_sniffing(self):
        if not self.sniffing:
            self.sniffing = True
            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)
            self.save_button.config(state=tk.NORMAL)
            self.save_as_button.config(state=tk.NORMAL)
            self.sniff_thread = threading.Thread(target=self.sniff_packets)
            self.sniff_thread.daemon = True
            self.sniff_thread.start()

    def stop_sniffing(self):
        self.sniffing = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.save_button.config(state=tk.DISABLED)
        self.save_as_button.config(state=tk.DISABLED)

    def sniff_packets(self):
        sniff(prn=self.packet_callback, store=0, stop_filter=lambda p: not self.sniffing)

    def save_file(self):
        if hasattr(self, 'current_file'):
            with open(self.current_file, 'w') as file:
                file.writelines(self.packet_data)
        else:
            self.save_as_file()

    def save_as_file(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".txt",
                                                 filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if file_path:
            self.current_file = file_path
            with open(file_path, 'w') as file:
                file.writelines(self.packet_data)

def main():
    root = tk.Tk()
    app = PacketAnalyzerApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
