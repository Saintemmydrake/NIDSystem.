import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
from PIL import Image, ImageTk  # Import Pillow
import re

# Declare global variables
user_email = ""
user_ipv4 = ""
store = ""

def on_select(event):
    selected = selected_option.get()
    print("You selected:", selected)

def validate_email(email):
    pattern = re.compile(r"[^@]+@[^@]+\.[^@]+")
    return pattern.match(email)

def validate_ipv4(ip):
    pattern = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
    if pattern.match(ip):
        parts = ip.split('.')
        for part in parts:
            if int(part) < 0 or int(part) > 255:
                return False
        return True
    return False

def on_submit():
    global user_email, user_ipv4, store  # Use global variables
    user_email = email_entry.get()
    user_ipv4 = ipv4_entry.get()
    store = selected_option.get()

    if not validate_email(user_email):
        messagebox.showerror("Invalid Email", "Please enter a valid email address.")
        return

    if not validate_ipv4(user_ipv4):
        messagebox.showerror("Invalid IPv4 Address", "Please enter a valid IPv4 address.")
        return
    root.destroy()

# Create the main window
root = tk.Tk()
root.title("NID System")

# Window dimensions
window_width = 700
window_height = 700

# Screen resolution
screen_width = root.winfo_screenwidth()
screen_height = root.winfo_screenheight()

# Calculate the position to center the window on the screen
position_top = int(screen_height / 2 - window_height / 2)
position_right = int(screen_width / 2 - window_width / 2)

# Set the dimensions and position of the window
root.geometry(f'{window_width}x{window_height}+{position_right}+{position_top}')

# Create a canvas
canvas = tk.Canvas(root, width=window_width, height=window_height)
canvas.pack(fill="both", expand=True)

# Load the background image (make sure to fix the path)
background_image = Image.open(r"C:/Users/USER/Pictures/des.jpg")  # Use a valid path
background_image = background_image.resize((window_width, window_height))  # No ANTIALIAS
bg_image = ImageTk.PhotoImage(background_image)

# Create an image on the canvas
canvas.create_image(0, 0, anchor=tk.NW, image=bg_image)

# Create a frame to hold the widgets (to avoid overlapping with the background)
frame = ttk.Frame(canvas)
frame.place(relx=0.5, rely=0.5, anchor=tk.CENTER)

label = ttk.Label(frame, text="Welcome to Saint's NIDS")
label.pack(pady=10)

# Create a label and textbox for email input
email_label = ttk.Label(frame, text="Input your Email Address:")
email_label.pack(pady=10)

email_entry = ttk.Entry(frame, width=35)
email_entry.pack(pady=10)

# Create a label and textbox for IPv4 input
ipv4_label = ttk.Label(frame, text="Enter your IPv4 Address:")
ipv4_label.pack(pady=10)

ipv4_entry = ttk.Entry(frame, width=35)
ipv4_entry.pack(pady=10)

# Create a label for the drop-down list
label = ttk.Label(frame, text="Select an action you want to perform.")
label.pack(pady=10)

# Create a variable to store the selected option
selected_option = tk.StringVar()

# Create the drop-down list
dropdown = ttk.Combobox(frame, textvariable=selected_option, width=35)
dropdown['values'] = ("Packet_Sniffer", "Traffic Analyzer", "Anomaly Detector")
dropdown['state'] = 'readonly'
dropdown.pack(pady=20)

# Bind the selection event to the callback function
dropdown.bind("<<ComboboxSelected>>", on_select)

# Create a Submit button to print the input values
submit_button = ttk.Button(frame, text="Submit", command=on_submit)
submit_button.pack(pady=10)

# Run the application
root.mainloop()
