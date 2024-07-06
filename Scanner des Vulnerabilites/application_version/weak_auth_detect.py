import requests

# Function to load passwords from a file
def load_passwords(file_path):
    with open(file_path, 'r') as file:
        passwords = file.read().splitlines()
    return passwords

# Function to check for common weak passwords
def check_common_passwords(url, username, passwords):
    for password in passwords:
        response = requests.post(url, data={'username': username, 'password': password})
        if response.status_code == 200:
            print(f"Weak password found: {password}")
            return True, f"Weak password found: {password}"
    return False, "No weak passwords found."

# Brute force attack simulation
def brute_force_attack(url, username, password_list):
    for password in password_list:
        response = requests.post(url, data={'username': username, 'password': password})
        if response.status_code == 200:
            print(f"Password found: {password}")
            return True, f"Password found: {password}"
    return False, "Brute force attack failed. No password found."

# Checking for account lockout mechanism
def check_account_lockout(url, username):
    for i in range(10):
        response = requests.post(url, data={'username': username, 'password': 'wrongpassword'})
        if response.status_code == 429:  # Too Many Requests
            print("Account lockout mechanism detected.")
            return True, "Account lockout mechanism detected."
    print("No account lockout mechanism detected.")
    return False, "No account lockout mechanism detected."

# Combine functions and execute
def scan_weak_auth(url, username, password_file):
    passwords = load_passwords(password_file)
    results = []
    
    # Check for common weak passwords
    found, description = check_common_passwords(url, username, passwords)
    results.append(("Common Passwords", found, description))
    
    # Simulate brute force attack
    found, description = brute_force_attack(url, username, passwords)
    results.append(("Brute Force", found, description))
    
    # Check for account lockout mechanism
    found, description = check_account_lockout(url, username)
    results.append(("Account Lockout", found, description))

    return results
