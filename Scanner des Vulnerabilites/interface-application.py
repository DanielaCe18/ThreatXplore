#!/usr/bin/env python3
# coding:utf-8
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from PIL import Image, ImageTk

# Function to scan for vulnerabilities
def scan_vulnerabilities():
    url = entry.get()
    if url:
        vulnerabilities_found = True  # Placeholder for actual scanning logic
        if vulnerabilities_found:
            result_text.set("Vulnerabilities found!")
            result_label.config(foreground="red")
            red_team_button.config(state=tk.NORMAL)
            blue_team_button.config(state=tk.NORMAL)
        else:
            result_text.set("No vulnerabilities found.")
            result_label.config(foreground="green")
    else:
        messagebox.showwarning("Input Error", "Please enter a URL.")

# Function for Red Team action
def red_team_action():
    messagebox.showinfo("Red Team", "Executing Red Team actions...")

# Function for Blue Team action
def blue_team_action():
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

# Function to show help information
def show_help():
    messagebox.showinfo("Help", "To use this scanner:\n1. Enter a URL.\n2. Click 'Scan'.\n3. Choose Red or Blue Team action.\n4. Download the report.")

# Initialize the main application window
root = tk.Tk()
root.title("Vulnerability Scanner")
root.geometry("1080x720")
root.minsize(480, 360)
root.config(background="#1e1e1e")

# Configure styles
style = ttk.Style()
style.configure("TFrame", background="#1e1e1e")
style.configure("TLabel", background="#1e1e1e", foreground="#ffffff", font=("Arial", 15))
style.configure("TButton", background="#3a3a3a", foreground="#ffffff", font=("Arial", 15), padding=10)
style.map("TButton", background=[("active", "#565656")])

# Add menu bar with Help
menu_bar = tk.Menu(root)
help_menu = tk.Menu(menu_bar, tearoff=0)
help_menu.add_command(label="Help", command=show_help)
menu_bar.add_cascade(label="Help", menu=help_menu)
root.config(menu=menu_bar)

# Create and place frames for better layout management
header_frame = ttk.Frame(root)
header_frame.pack(pady=20)

input_frame = ttk.Frame(root)
input_frame.pack(pady=20)

action_frame = ttk.Frame(root)
action_frame.pack(pady=20)

result_frame = ttk.Frame(root)
result_frame.pack(pady=20)

# Load and display logo
logo = Image.open("logo.png")  # Replace with your logo file path
logo = logo.resize((100, 100), Image.LANCZOS)
logo = ImageTk.PhotoImage(logo)
logo_label = ttk.Label(header_frame, image=logo, background="#1e1e1e")
logo_label.pack(side=tk.LEFT, padx=20)

# Title label
title_label = ttk.Label(header_frame, text="Vulnerability Scanner", font=("Arial", 35, "bold"))
title_label.pack(side=tk.LEFT, padx=20)

# URL entry
entry_label = ttk.Label(input_frame, text="Enter URL:")
entry_label.grid(row=0, column=0, padx=10, pady=10, sticky=tk.E)
entry = ttk.Entry(input_frame, font=("Arial", 15), width=50)
entry.grid(row=0, column=1, padx=10, pady=10, sticky=tk.W)

# Scan button
scan_button = ttk.Button(input_frame, text="Scan", command=scan_vulnerabilities)
scan_button.grid(row=0, column=2, padx=10, pady=10)

# Result label
result_text = tk.StringVar()
result_label = ttk.Label(result_frame, textvariable=result_text, font=("Arial", 20))
result_label.pack()

# Red Team button
red_team_button = ttk.Button(action_frame, text="Red Team Action", command=red_team_action, state=tk.DISABLED)
red_team_button.grid(row=0, column=0, padx=20, pady=10)

# Blue Team button
blue_team_button = ttk.Button(action_frame, text="Blue Team Action", command=blue_team_action, state=tk.DISABLED)
blue_team_button.grid(row=0, column=1, padx=20, pady=10)

# Download report button
download_button = ttk.Button(root, text="Download Report", command=download_report)
download_button.pack(pady=20)

root.mainloop()
