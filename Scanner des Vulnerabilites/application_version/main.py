import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from tkinter.font import Font
from PIL import Image, ImageTk
import re
import logging
import whois_scan
import asyncio

# Import only when needed
import importlib

# Configure logging
logging.basicConfig(filename='vulnerability_scanner.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Vulnerability descriptions
vulnerability_descriptions = {
    'OS Command Injection': (
        "OS Command Injection is a web security vulnerability that allows an attacker to execute arbitrary "
        "operating system commands on the server running an application, which can compromise the entire server."
    ),
    'SQL Injection': (
        "SQL Injection is a web security vulnerability that allows an attacker to interfere with the queries "
        "that an application makes to its database. This can result in unauthorized access to sensitive data, "
        "modification of database content, or even administrative operations on the database."
    ),
    'XSS': (
        "Cross-Site Scripting (XSS) is a web security vulnerability that allows an attacker to inject malicious "
        "scripts into content from otherwise trusted websites. The attacker can use this to hijack user sessions, "
        "deface websites, or redirect the user to malicious sites."
    ),
    'Email Disclosure': (
        "Email Disclosure is a vulnerability that allows an attacker to find email addresses disclosed in the "
        "webpage content. This can lead to spam, phishing, or other social engineering attacks."
    ),
    'Credit Card Disclosure': (
        "Credit Card Disclosure is a vulnerability where credit card information is exposed in the webpage content. "
        "This can lead to unauthorized financial transactions and identity theft."
    ),
    'SSTI': (
        "Server-Side Template Injection (SSTI) is a vulnerability that allows an attacker to inject malicious code "
        "into a template, which is then executed server-side. This can lead to remote code execution, data theft, "
        "and other serious attacks."
    ),
    'WebSocket': (
        "WebSocket vulnerabilities can allow an attacker to inject malicious payloads into the WebSocket connection, "
        "leading to issues such as XSS, SQL Injection, directory traversal, and more."
    ),
    'CORS': (
        "Cross-Origin Resource Sharing (CORS) vulnerabilities allow an attacker to bypass the Same-Origin Policy, "
        "which can lead to unauthorized access to resources and sensitive data from another origin."
    ),
    'CSRF': (
        "Cross-Site Request Forgery (CSRF) is a vulnerability that tricks a user into submitting a malicious request. "
        "It allows an attacker to perform actions on behalf of the user without their consent."
    ),
    'File Upload': (
        "File Upload vulnerabilities allow an attacker to upload malicious files to the server. These files can be "
        "executed on the server, leading to remote code execution, data theft, or other malicious activities."
    ),
    'LFI': (
        "Local File Inclusion (LFI) is a vulnerability that allows an attacker to include files on a server through "
        "the web browser. This can lead to sensitive information disclosure, remote code execution, and other attacks."
    ),
    'Path Traversal': (
        "Path Traversal is a vulnerability that allows an attacker to access files on the server that are outside "
        "the web root directory. This can lead to disclosure of sensitive information, modification of files, and "
        "other attacks."
    ),
    'Robots.txt': (
        "The robots.txt file is used to manage and restrict the activities of search engine crawlers on a website. "
        "However, it can also reveal sensitive information and paths to attackers if not handled properly."
    ),
    'SSRF': (
        "Server-Side Request Forgery (SSRF) is a vulnerability that allows an attacker to make requests to internal "
        "or external services from a vulnerable server. This can lead to unauthorized access to internal systems, "
        "sensitive data exposure, and other attacks."
    ),
    'Subdomain Enumeration': (
        "Subdomain Enumeration involves discovering subdomains associated with a main domain. It can reveal forgotten, "
        "unsecured, or potentially vulnerable subdomains, which can be exploited by attackers."
    ),
    'Common Passwords': (
        "Common Passwords detection involves checking if an application allows the use of weak or commonly used passwords, "
        "which can compromise the security of user accounts."
    ),
    'Brute Force': (
        "Brute Force detection involves testing a large number of passwords against a given username to find the correct password. "
        "If successful, it indicates a vulnerability to brute force attacks."
    ),
    'Account Lockout': (
        "Account Lockout detection involves checking if the application has mechanisms in place to lock an account "
        "after a certain number of failed login attempts, preventing brute force attacks."
    ),
    'XXE': (
        "XML External Entity (XXE) injection is a web security vulnerability that allows an attacker to interfere with the processing of XML data. "
        "It can lead to exposure of internal files, SSRF, and other serious attacks."
    ),
    'Uncommon HTTP Methods': (
        "Uncommon HTTP Methods like OPTIONS, TRACE, CONNECT, PUT, DELETE may be allowed and can be exploited by attackers "
        "to perform various malicious actions."
    ),
    'HTTP Redirections': (
        "HTTP Redirections can be exploited by attackers to redirect users to malicious sites or phishing pages. "
        "Improperly handled redirections may lead to security issues."
    ),
    'Security Headers': (
        "Security Headers are important to protect against common web vulnerabilities. Missing headers like Content-Security-Policy, "
        "X-Content-Type-Options, X-Frame-Options, etc., can make the application more vulnerable to attacks."
    ),
    'Open Ports': (
        "Open Ports detection involves scanning a target for open ports, which can reveal running services and potential vulnerabilities. "
        "This can help in identifying security risks associated with exposed services."
    )
}

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

    selected_scan = scan_type_var.get()
    if not selected_scan:
        messagebox.showwarning("No Selection", "Please select a type of scan.")
        return

    logging.info(f"Started scan for URL: {url} with scan: {selected_scan}")
    progress.start()
    root.after(2000, lambda: scan_vulnerabilities(selected_scan))  # Simulate a scan delay

# Function to scan for vulnerabilities
def scan_vulnerabilities(selected_scan):
    global scan_results  # Correct placement of global declaration
    progress.stop()
    url = entry.get()
    results = []

    module_map = {
        'OS Command Injection': 'OS_command_injection',
        'SQL Injection': 'sqli_xss_detect',
        'XSS': 'sqli_xss_detect',
        'SSTI': 'SSTI_detect',
        'WebSocket': 'WebSocket',
        'CORS': 'cors_detect',
        'CSRF': 'csrf_detector',
        'File Upload': 'file_upload',
        'LFI': 'lfi_detect',
        'Path Traversal': 'path_traversal',
        'Robots.txt': 'robot_detect',
        'SSRF': 'ssrf_detect',
        'Subdomain Enumeration': 'subdomain_enum',
        'Common Passwords': 'weak_auth_detect',
        'Brute Force': 'weak_auth_detect',
        'Account Lockout': 'weak_auth_detect',
        'XXE': 'xxe_detect',
        'Uncommon HTTP Methods': 'http_vuln',
        'HTTP Redirections': 'http_vuln',
        'Security Headers': 'http_vuln',
        'Open Ports': 'scan_open_ports',
        'WHOIS': 'whois_scan',
        'General Info': 'scangen',
        'Email Disclosure': 'email_card_detect',
        'Credit Card Disclosure': 'email_card_detect'
    }

    try:
        module = importlib.import_module(module_map[selected_scan])
    except ImportError as e:
        messagebox.showerror("Import Error", f"Failed to import module for {selected_scan}: {str(e)}")
        return

    if selected_scan == 'OS Command Injection':
        vulnerabilities_found, description = module.scan_os_command_injection(url)
        if vulnerabilities_found:
            results.append(("Vulnerabilities found!", "OS Command Injection", description))
        else:
            results.append(("No vulnerabilities found.", "OS Command Injection", description))
    
    elif selected_scan == 'SQL Injection':
        vulnerabilities_found, description = module.scan_sql(url)
        if vulnerabilities_found:
            results.append(("Vulnerabilities found!", "SQL Injection", description))
        else:
            results.append(("No vulnerabilities found.", "SQL Injection", description))
    
    elif selected_scan == 'XSS':
        vulnerabilities_found, description = module.scan_xss(url)
        if vulnerabilities_found:
            results.append(("Vulnerabilities found!", "XSS", description))
        else:
            results.append(("No vulnerabilities found.", "XSS", description))

    elif selected_scan == 'Email Disclosure':
        emails = module.find_emails(url)
        description = "\n".join(emails) if emails else "No email addresses found."
        if emails:
            results.append(("Vulnerabilities found!", "Email Disclosure", description))
        else:
            results.append(("No vulnerabilities found.", "Email Disclosure", description))

    elif selected_scan == 'Credit Card Disclosure':
        credit_cards = module.find_credit_cards(url)
        description = "\n".join(credit_cards) if credit_cards else "No credit card information found."
        if credit_cards:
            results.append(("Vulnerabilities found!", "Credit Card Disclosure", description))
        else:
            results.append(("No vulnerabilities found.", "Credit Card Disclosure", description))

    elif selected_scan == 'SSTI':
        vulnerabilities_found, engine, payload = module.check_ssti(url, "message")  # Replace "message" with actual parameter
        description = f"SSTI vulnerability detected with {engine} payload: {payload}" if vulnerabilities_found else "No SSTI vulnerabilities found."
        if vulnerabilities_found:
            results.append(("Vulnerabilities found!", "SSTI", description))
        else:
            results.append(("No vulnerabilities found.", "SSTI", description))

    elif selected_scan == 'WebSocket':
        url = module.transform_url_to_ws(url)
        vulnerabilities_found = asyncio.run(module.test_websocket(url))
        if vulnerabilities_found:
            description = '\n'.join(vulnerabilities_found)
            results.append(("Vulnerabilities found!", "WebSocket", description))
        else:
            results.append(("No vulnerabilities found.", "WebSocket", "No WebSocket vulnerabilities detected."))

    elif selected_scan == 'CORS':
        exploit_server_url = "https://exploit-0a8d004004b6bc7486346adb017d0039.exploit-server.net"
        base_url = entry.get()
        login_url = f"{base_url}/login"  # Replace with actual login URL
        target_url = f"{base_url}/accountDetails"  # Replace with actual target URL
        evil_origin = "https://example.com"   # Replace with actual evil origin
        username = "wiener"  # Replace with actual username
        password = "peter"  # Replace with actual password
        session = module.login_and_get_session(login_url, username, password)
        if session:
            vulnerabilities_found, cors_details = module.check_cors_vulnerability(session, target_url, evil_origin)
            description = f"CORS vulnerability detected. Details: {cors_details}" if vulnerabilities_found else "No CORS vulnerabilities found."
            results.append(("Vulnerabilities found!", "CORS", description)) if vulnerabilities_found else results.append(("No vulnerabilities found.", "CORS", description))
        else:
            results.append(("Failed to login.", "CORS", "Could not log in to test for CORS vulnerability."))

    elif selected_scan == 'CSRF':
        base_url = entry.get()
        description = module.detect_csrf_vulnerability(base_url)
    
        if "likely vulnerable" in description:
            results.append(("Vulnerabilities found!", "CSRF", description))
        else:
            results.append(("No vulnerabilities found.", "CSRF", description))

    elif selected_scan == 'File Upload':
        session = module.create_session()
        username = "bee"  # Replace with actual username
        password = "bug"  # Replace with actual password
    
        # Login and then check the specific file upload URL
        module.login(session, url, username, password)
        file_upload_url = f"{url}/unrestricted_file_upload.php"  # Ensure this matches the URL you are checking
    
        vulnerabilities_found, description = module.file_upload_vulnerability(session, file_upload_url)
        if vulnerabilities_found:
            results.append(("Vulnerabilities found!", "File Upload", description))
        else:
            results.append(("No vulnerabilities found.", "File Upload", description))
    
    elif selected_scan == 'LFI':
        vulnerabilities_found, description = module.advanced_lfi_detection(url)
        if vulnerabilities_found:
            results.append(("Vulnerabilities found!", "LFI", description))
        else:
            results.append(("No vulnerabilities found.", "LFI", description))
    
    elif selected_scan == 'Path Traversal':
        vulnerabilities_found, description = module.check_path_traversal(url)
        if vulnerabilities_found:
            results.append(("Vulnerabilities found!", "Path Traversal", description))
        else:
            results.append(("No vulnerabilities found.", "Path Traversal", description))

    elif selected_scan == 'Robots.txt':
        vulnerabilities_found, description = module.check_robots_txt(url)
        if vulnerabilities_found:
            results.append(("Vulnerabilities found!", "Robots.txt", description))
        else:
            results.append(("No vulnerabilities found.", "Robots.txt", description))

    elif selected_scan == 'SSRF':
        vulnerabilities_found, description = module.test_ssrf_post(url)
        if vulnerabilities_found:
            results.append(("Vulnerabilities found!", "SSRF", description))
        else:
            results.append(("No vulnerabilities found.", "SSRF", description))

    elif selected_scan == 'Subdomain Enumeration':
        vulnerabilities_found, description = module.main(url)
        if vulnerabilities_found:
            results.append(("Vulnerabilities found!", "Subdomain Enumeration", description))
        else:
            results.append(("No vulnerabilities found.", "Subdomain Enumeration", description))

    elif selected_scan == 'Common Passwords':
        username = "bee"  # Replace with actual username
        password_file = 'common-password.txt'  # Replace with actual password file path
        vulnerabilities_found, description = module.check_common_passwords(url, username, module.load_passwords(password_file))
        if vulnerabilities_found:
            results.append(("Vulnerabilities found!", "Common Passwords", description))
        else:
            results.append(("No vulnerabilities found.", "Common Passwords", description))

    elif selected_scan == 'Brute Force':
        username = "bee"  # Replace with actual username
        password_file = 'common-password.txt'  # Replace with actual password file path
        vulnerabilities_found, description = module.brute_force_attack(url, username, module.load_passwords(password_file))
        if vulnerabilities_found:
            results.append(("Vulnerabilities found!", "Brute Force", description))
        else:
            results.append(("No vulnerabilities found.", "Brute Force", description))

    elif selected_scan == 'Account Lockout':
        username = "bee"  # Replace with actual username
        vulnerabilities_found, description = module.check_account_lockout(url, username)
        if vulnerabilities_found:
            results.append(("Vulnerabilities found!", "Account Lockout", description))
        else:
            results.append(("No vulnerabilities found.", "Account Lockout", description))

    elif selected_scan == 'XXE':
        vulnerabilities_found, description = module.scan_xxe(url)
        if vulnerabilities_found:
            results.append(("Vulnerabilities found!", "XXE", description))
        else:
            results.append(("No vulnerabilities found.", "XXE", description))

    elif selected_scan == 'Uncommon HTTP Methods':
        methods_results = module.check_uncommon_http_methods(url)
        for method, result in methods_results.items():
            description = result['reason']
            if result['vulnerability']:
                results.append(("Vulnerabilities found!", f"Uncommon HTTP Method: {method}", description))
            else:
                results.append(("No vulnerabilities found.", f"Uncommon HTTP Method: {method}", description))
    
    elif selected_scan == 'HTTP Redirections':
        redirection_result = module.check_redirections(url)
        description = redirection_result['reason']
        if redirection_result['vulnerability']:
            results.append(("Vulnerabilities found!", "HTTP Redirections", description))
        else:
            results.append(("No vulnerabilities found.", "HTTP Redirections", description))
    
    elif selected_scan == 'Security Headers':
        headers_result = module.check_security_headers(url)
        description = headers_result['reason']
        if headers_result['vulnerability']:
            results.append(("Vulnerabilities found!", "Security Headers", description))
        else:
            results.append(("No vulnerabilities found.", "Security Headers", description))
    
    elif selected_scan == 'Open Ports':
        options = "-sS -sV -O -p- --script=vuln"
        nm = module.scan_ports(url, options)
        scan_results = module.get_scan_results(nm)
        if scan_results:
            for result in scan_results:
                results.append(("Vulnerabilities found!", "Open Ports", json.dumps(result)))
        else:
            results.append(("No vulnerabilities found.", "Open Ports", "No open ports detected."))

    elif selected_scan == 'WHOIS':
        try:
            w = module.fetch_whois_info(url)
            whois_info = module.format_whois_info(w)
            result_text_box.config(state=tk.NORMAL)
            result_text_box.delete(1.0, tk.END)
            result_text_box.insert(tk.END, whois_info)
            result_text_box.config(state=tk.DISABLED)
            return  # Exit the function as WHOIS doesn't need further processing
        except Exception as e:
            result_text_box.config(state=tk.NORMAL)
            result_text_box.delete(1.0, tk.END)
            result_text_box.insert(tk.END, f"Failed to fetch WHOIS info: {str(e)}")
            result_text_box.config(state=tk.DISABLED)
            return

    elif selected_scan == 'General Info':
        try:
            general_info = module.scan_general_info(url)
            result_text_box.config(state=tk.NORMAL)
            result_text_box.delete(1.0, tk.END)
            for key, info in general_info.items():
                result_text_box.insert(tk.END, f"{key.capitalize()}: {info}\n", "black")
            result_text_box.config(state=tk.DISABLED)
            return  # Exit the function as General Info doesn't need further processing
        except Exception as e:
            result_text_box.config(state=tk.NORMAL)
            result_text_box.delete(1.0, tk.END)
            result_text_box.insert(tk.END, f"Failed to fetch General Info: {str(e)}")
            result_text_box.config(state=tk.DISABLED)
            return

    # Display results in the white text box
    result_text_box.config(state=tk.NORMAL)
    result_text_box.delete(1.0, tk.END)
    for status, name, description in results:
        color = "red" if "Vulnerabilities found!" in status else "green"
        result_text_box.insert(tk.END, f"{status} ", (color,))
        result_text_box.insert(tk.END, f"{name}:\n", "black")
        result_text_box.insert(tk.END, f"{vulnerability_descriptions[name]}\n\n", "black")
    result_text_box.config(state=tk.DISABLED)
    
    # Store the scan results for the Red Team button action
    scan_results = results

    # Enable the Red and Blue Team buttons
    red_team_button.config(state=tk.NORMAL)
    blue_team_button.config(state=tk.NORMAL)

    logging.info(f"Scan results for URL: {url} - {results}")

# Function for Red Team action
def red_team_action():
    logging.info("Red Team action executed.")
    detailed_results = '\n\n'.join(f"{status} {name}:\n{description}" for status, name, description in scan_results)
    messagebox.showinfo("Red Team", detailed_results)

# Function for Blue Team action
def blue_team_action():
    logging.info("Blue Team action executed.")
    prevention_message = (
        "To protect against vulnerabilities:\n"
        "1. Validate and sanitize all user inputs.\n"
        "2. Use parameterized queries and prepared statements for SQL.\n"
        "3. Encode output to prevent XSS.\n"
        "4. Employ security libraries and frameworks."
    )
    messagebox.showinfo("Blue Team", prevention_message)

# Function to download the report
def download_report():
    file_path = filedialog.asksaveasfilename(defaultextension=".txt",
                                             filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
    if file_path:
        with open(file_path, 'w') as file:
            file.write("Vulnerability Scan Report\n")
            file.write("URL: " + entry.get() + "\n")
            detailed_results = '\n\n'.join(f"{status} {name}:\n{description}" for status, name, description in scan_results)
            file.write("Results:\n" + detailed_results + "\n")
        messagebox.showinfo("Download Complete", "Report downloaded successfully!")
        logging.info("Report downloaded.")

# Function to show help information
def show_help():
    messagebox.showinfo("Help", "To use this scanner:\n1. Enter a URL.\n2. Select the type of scan.\n3. Click 'Scan'.\n4. Choose Red or Blue Team action.\n5. Download the report.")

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
style.configure("TButton", background="#dcdcdc", foreground="#000000", font=("Arial", 15), padding=10)
style.map("TButton", background=[("active", "#c0c0c0")])

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
logo_label = ttk.Label(header_frame, image=logo, background="#ADD8E6")
logo_label.pack(side=tk.LEFT, padx=20)

# Title label
title_label = ttk.Label(header_frame, text="ThreatXplore", font=("Arial", 35, "bold"))
title_label.pack(side=tk.LEFT, padx=20)

# URL entry
entry_label = ttk.Label(input_frame, text="Enter URL:")
entry_label.grid(row=0, column=0, padx=10, pady=10, sticky=tk.E)
entry = ttk.Entry(input_frame, font=("Arial", 15), width=50)
entry.grid(row=0, column=1, padx=10, pady=10, sticky=tk.W)

# Tooltips for URL entry
url_tooltip = ttk.Label(input_frame, text="Enter the URL you want to scan", background="#ADD8E6", foreground="#888")
url_tooltip.grid(row=1, column=1, pady=5)

# Scan options
scan_type_var = tk.StringVar()
scan_type_label = ttk.Label(input_frame, text="Select Scan Type:")
scan_type_label.grid(row=2, column=0, padx=10, pady=10, sticky=tk.E)
scan_type_combobox = ttk.Combobox(input_frame, textvariable=scan_type_var, values=[
    "OS Command Injection", "SQL Injection", "XSS", "SSTI", "WebSocket", "CORS", "CSRF", 
    "File Upload", "LFI", "Path Traversal", "Robots.txt", "SSRF", "Subdomain Enumeration",
    "Common Passwords", "Brute Force", "Account Lockout", "XXE", "Uncommon HTTP Methods", 
    "HTTP Redirections", "Security Headers", "Open Ports", "WHOIS", "General Info",
    "Email Disclosure", "Credit Card Disclosure"
], state="readonly")
scan_type_combobox.grid(row=2, column=1, padx=10, pady=10, sticky=tk.W)

# Scan button
scan_button = ttk.Button(input_frame, text="Scan", command=start_scan)
scan_button.grid(row=0, column=2, padx=10, pady=10)

# Progress bar
progress = ttk.Progressbar(input_frame, orient="horizontal", mode="indeterminate", length=300)
progress.grid(row=3, column=0, columnspan=3, pady=20)

# Result label
result_text = tk.StringVar()
result_label = ttk.Label(result_frame, textvariable=result_text, font=("Arial", 20), background="#ADD8E6")
result_label.pack()

# White text box for displaying scan results
result_text_box = tk.Text(result_frame, height=10, width=100, wrap=tk.WORD, background="white", font=("Arial", 12))
result_text_box.pack(pady=10)
result_text_box.tag_configure("red", foreground="red")
result_text_box.tag_configure("green", foreground="green")
result_text_box.tag_configure("black", foreground="black")
result_text_box.config(state=tk.DISABLED)

# Red Team button
red_team_button = ttk.Button(action_frame, text="Red Team Action", command=red_team_action, state=tk.DISABLED)
red_team_button.grid(row=0, column=0, padx=20, pady=10)
red_team_button.config(style="Red.TButton")

# Blue Team button
blue_team_button = ttk.Button(action_frame, text="Blue Team Action", command=blue_team_action, state=tk.DISABLED)
blue_team_button.grid(row=0, column=1, padx=20, pady=10)
blue_team_button.config(style="Blue.TButton")

# Download report button
download_button = ttk.Button(root, text="Download Report", command=download_report)
download_button.pack(pady=20)

# Configure styles for Red and Blue buttons
style.configure("Red.TButton", background="#ff0000", foreground="#ffffff")
style.configure("Blue.TButton", background="#0000ff", foreground="#ffffff")

root.mainloop()
