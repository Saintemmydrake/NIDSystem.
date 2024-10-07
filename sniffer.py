import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from scapy.all import sniff, conf
import threading

# Global variable to control the sniffer thread
sniffer_running = False

def on_select(event):
    stored = selected_option.get()
    result_text.insert(tk.END, f"You selected: {stored}\n")
    auto_scroll()

def on_submit():
    note = filter_entry.get()
    result_text.insert(tk.END, f"Stored Interface: {selected_option.get()}\n")
    result_text.insert(tk.END, f"Filter Note: {note}\n")
    auto_scroll()

def validate_filter(interface, filter_note):
    try:
        # Test the filter by creating a dummy sniffing operation
        conf.sniff_promisc = False
        sniff(iface=interface, filter=filter_note, count=1)
        return True
    except Exception as e:
        # Display the error message in the Text widget
        result_text.insert(tk.END, f"Errorr: {str(e)}\n")
        auto_scroll()  # Ensure the text widget scrolls to the bottom
        return False

def start_sniffing():
    global sniffer_running
    sniffer_running = True
    interface = selected_option.get()
    filter_note = filter_entry.get()

    # Validate the filter before starting sniffing
    if not validate_filter(interface, filter_note):
        result_text.insert(tk.END, "Sniffing did not start due to filter error.\n")
        auto_scroll()
        return  # Exit the function if validation fails

    # Proceed with sniffing if validation is successful
    result_text.insert(tk.END, "Packet sniffing started...\n")
    auto_scroll()
    try:
        sniff(iface=interface, filter=filter_note, prn=lambda x: display_packet(x), stop_filter=lambda _: not sniffer_running)
    except Exception as e:
        result_text.insert(tk.END, f"Error during sniffing: {str(e)}\n")
        auto_scroll()

def display_packet(packet):
    result_text.insert(tk.END, f"{packet.summary()}\n")
    auto_scroll()

def auto_scroll():
    result_text.yview_moveto(1.0)  # Scroll to the bottom

def on_start():
    sniffing_thread = threading.Thread(target=start_sniffing)
    sniffing_thread.daemon = True
    sniffing_thread.start()

def on_stop():
    global sniffer_running
    sniffer_running = False
    result_text.insert(tk.END, "Stopping packet sniffing...\n")
    auto_scroll()

def on_save():
    with open("results.txt", "w") as file:
        file.write(result_text.get("1.0", tk.END))
    result_text.insert(tk.END, "Results saved to results.txt\n")
    auto_scroll()

def on_save_as():
    file_path = filedialog.asksaveasfilename(defaultextension=".txt",
                                             filetypes=[("Text files", "*.txt"),
                                                        ("All files", ".")])
    if file_path:  # Check if the user provided a file path
        with open(file_path, "w") as file:
            file.write(result_text.get("1.0", tk.END))
        result_text.insert(tk.END, f"Results saved to {file_path}\n")
        auto_scroll()

# Create the main window
root = tk.Tk()
root.title("Packet Sniffer")

# Window dimensions
window_width = 700
window_height = 700

# Screen resolution
screen_width = 1366
screen_height = 768

# Calculate the position to center the window on the screen
position_top = int(screen_height / 2 - window_height / 2)
position_right = int(screen_width / 2 - window_width / 2)

# Set the dimensions and position of the window
root.geometry(f'{window_width}x{window_height}+{position_right}+{position_top}')

# Create a label for the drop-down list
label = ttk.Label(root, text="Select your Network Interface:")
label.pack(pady=5)

# Create a variable to store the selected option
selected_option = tk.StringVar()

# Create the drop-down list
dropdown = ttk.Combobox(root, textvariable=selected_option, width=32)
dropdown['values'] = ("Wi-Fi", "Ethernet", "Ethernet 2", "Bluetooth Network Connection")
dropdown['state'] = 'readonly'  # makes the combobox read-only
dropdown.pack(pady=10)

# Bind the selection event to the callback function
dropdown.bind("<<ComboboxSelected>>", on_select)

filter_label = ttk.Label(root, text="Filter(s)? (optional)")
filter_label.pack(pady=5)

filter_entry = ttk.Entry(root, width=35)
filter_entry.pack(pady=5)

# Create a submit button to process the data
submit_button = ttk.Button(root, text="Submit", command=on_submit)
submit_button.pack(pady=10)

# Create a Start button to start packet sniffing
start_button = ttk.Button(root, text="Start", command=on_start)
start_button.pack(pady=5)

# Create a Text widget to display results
result_text = tk.Text(root, height=25, width=100)
result_text.pack(pady=10)

# Create a frame to hold the Stop, Save, and Save As buttons within the results pane
result_button_frame = ttk.Frame(root)
result_button_frame.pack(pady=5)

# Create the Stop, Save, and Save As buttons within the results pane
stop_button = ttk.Button(result_button_frame, text="Stop", command=on_stop)
stop_button.grid(row=0, column=0, padx=5)

save_button = ttk.Button(result_button_frame, text="Save", command=on_save)
save_button.grid(row=0, column=1, padx=5)

save_as_button = ttk.Button(result_button_frame, text="Save As", command=on_save_as)
save_as_button.grid(row=0, column=2, padx=5)

# Run the application
root.mainloop()
