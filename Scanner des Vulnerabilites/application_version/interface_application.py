#!/usr/bin/env python3
# coding:utf-8
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from tkinter.font import Font
from PIL import Image, ImageTk
import re
import logging

# Configure logging
logging.basicConfig(filename='vulnerability_scanner.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Function to validate URL
def validate_url(url):
    regex = re.compile(
        r'^(?:http|ftp)s?://'  # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # domain...
        r'localhost|'  # localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|'  # ...or ipv4
        r'\[?[A-F0-9]*:[A-F0-9:]+\]?)'  # ...or ipv6
        r'(?::\d+)?'  # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    return re.match(regex, url) is not None

# Function to start scan
def start_scan():
    url = entry.get()
    if not validate_url(url):
        messagebox.showwarning("Invalid URL", "Please enter a valid URL.")
        return

    logging.info(f"Started scan for URL: {url}")
    progress.start()
    root.after(2000, scan_vulnerabilities)  # Simulate a scan delay

# Function to scan for vulnerabilities
def scan_vulnerabilities():
    progress.stop()
    url = entry.get()
    vulnerabilities_found = True  # Placeholder for actual scanning logic
    if vulnerabilities_found:
        result_text.set("Vulnerabilities found!")
        result_label.config(foreground="red")
        red_team_button.config(state=tk.NORMAL)
        blue_team_button.config(state=tk.NORMAL)
        logging.info(f"Vulnerabilities found for URL: {url}")
    else:
        result_text.set("No vulnerabilities found.")
        result_label.config(foreground="green")
        logging.info(f"No vulnerabilities found for URL: {url}")

# Function for Red Team action
def red_team_action():
    logging.info("Red Team action executed.")
    messagebox.showinfo("Red Team", "Executing Red Team actions...")

# Function for Blue Team action
def blue_team_action():
    logging.info("Blue Team action executed.")
    messagebox.showinfo("Blue Team", "Executing Blue Team actions...")

# Function to download the report
def download_report():
    file_path = filedialog.asksaveasfilename(defaultextension=".txt",
                                             filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
    if file_path:
        with open(file_path, 'w') as file:
            file.write("Vulnerability Scan Report\n")
            file.write("URL: " + entry.get() + "\n")
            file.write("Result: " + result_text.get() + "\n")
        messagebox.showinfo("Download Complete", "Report downloaded successfully!")
        logging.info("Report downloaded.")

# Function to show help information
def show_help():
    messagebox.showinfo("Help", "To use this scanner:\n1. Enter a URL.\n2. Click 'Scan'.\n3. Choose Red or Blue Team action.\n4. Download the report.")

# Initialize the main application window
root = tk.Tk()
root.title("ThreatXplore")
root.geometry("1080x720")
root.minsize(480, 360)
root.config(background="#ADD8E6")

# Configure styles
style = ttk.Style()
style.configure("TFrame", background="#ADD8E6")
style.configure("TLabel", background="#ADD8E6", foreground="#000000", font=("Arial", 15))
style.configure("TButton", font=("Arial", 15), padding=10)
style.map("TButton", background=[("active", "#c0c0c0")])

# Add menu bar with Help
menu_bar = tk.Menu(root)
help_menu = tk.Menu(menu_bar, tearoff=0)
help_menu.add_command(label="Help", command=show_help)
menu_bar.add_cascade(label="Help", menu=help_menu)
root.config(menu=menu_bar)

# Create a canvas for scrolling
canvas = tk.Canvas(root, background="#ADD8E6")
canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

# Add a scrollbar to the canvas
scrollbar = ttk.Scrollbar(root, orient=tk.VERTICAL, command=canvas.yview)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
canvas.configure(yscrollcommand=scrollbar.set)

# Create a frame to contain the widgets
main_frame = tk.Frame(canvas, background="#ADD8E6")

# Add the main frame to the canvas
canvas_window = canvas.create_window((0, 0), window=main_frame, anchor="nw")

# Create and place frames for better layout management
header_frame = tk.Frame(main_frame, background="#ADD8E6")
header_frame.pack(pady=20)

input_frame = tk.Frame(main_frame, background="#ADD8E6")
input_frame.pack(pady=20)

result_frame = tk.Frame(main_frame, background="#ADD8E6")
result_frame.pack(pady=20)

action_frame = tk.Frame(main_frame, background="#ADD8E6")
action_frame.pack(pady=20)

# Load and display logo
logo = Image.open("logo.png")  # Replace with your logo file path
logo = logo.resize((100, 100), Image.LANCZOS)
logo = ImageTk.PhotoImage(logo)
logo_label = ttk.Label(header_frame, image=logo, background="#ADD8E6")
logo_label.pack()

# Title label
title_label = ttk.Label(header_frame, text="ThreatXplore", font=("Arial", 35, "bold"), background="#ADD8E6")
title_label.pack()

# URL entry
entry_label = ttk.Label(input_frame, text="Enter URL:", background="#ADD8E6")
entry_label.grid(row=0, column=0, padx=10, pady=10, sticky="e")
entry = ttk.Entry(input_frame, font=("Arial", 15), width=50)
entry.grid(row=0, column=1, padx=10, pady=10)

# Tooltips for URL entry
url_tooltip = ttk.Label(input_frame, text="Enter the URL you want to scan", background="#ADD8E6", foreground="#888")
url_tooltip.grid(row=1, column=1, pady=5, sticky="w")

# Scan button
scan_button = ttk.Button(input_frame, text="Scan", command=start_scan)
scan_button.grid(row=0, column=2, padx=10, pady=10)

# Progress bar
progress = ttk.Progressbar(input_frame, orient="horizontal", mode="indeterminate", length=300)
progress.grid(row=2, column=0, columnspan=3, pady=20)

# Findings label
findings_label = ttk.Label(result_frame, text="Findings", font=("Arial", 20), background="#ADD8E6")
findings_label.pack(pady=10)

# Result label
result_text = tk.StringVar()
result_label = tk.Label(result_frame, textvariable=result_text, font=("Arial", 20), background="white", width=50, height=10, relief="sunken", anchor="nw")
result_label.pack(pady=10)

# Red Team button
red_team_button = tk.Button(result_frame, text="Red Team Action", command=red_team_action, state=tk.DISABLED, bg="red", fg="white", font=("Arial", 15), padx=10, pady=10)
red_team_button.pack(side=tk.LEFT, padx=20, pady=10)

# Blue Team button
blue_team_button = tk.Button(result_frame, text="Blue Team Action", command=blue_team_action, state=tk.DISABLED, bg="blue", fg="white", font=("Arial", 15), padx=10, pady=10)
blue_team_button.pack(side=tk.RIGHT, padx=20, pady=10)

# Download report button
download_button = ttk.Button(main_frame, text="Download Report", command=download_report)
download_button.pack(pady=20)

# Update the scroll region and center the main frame
def on_configure(event):
    canvas.configure(scrollregion=canvas.bbox("all"))
    canvas_width = event.width
    canvas_height = event.height
    main_frame_width = main_frame.winfo_reqwidth()
    main_frame_height = main_frame.winfo_reqheight()

    # Center the main_frame horizontally and vertically
    x_offset = max((canvas_width - main_frame_width) // 2, 0)
    y_offset = max((canvas_height - main_frame_height) // 2, 0)
    canvas.coords(canvas_window, x_offset, y_offset)

canvas.bind("<Configure>", on_configure)

# Bind the mouse wheel to scroll
def on_mouse_wheel(event):
    canvas.yview_scroll(-1 * int((event.delta / 120)), "units")

canvas.bind_all("<MouseWheel>", on_mouse_wheel)

root.mainloop()
