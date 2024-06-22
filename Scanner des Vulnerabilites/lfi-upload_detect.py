from bs4 import BeautifulSoup
import json
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

# Function to load JSON configuration
def load_config(file_path):
    with open(file_path, 'r') as json_file:
        return json.load(json_file)

# Function to send HTTP request
def send_request(session, url, payload):
    try:
        response = session.get(f"{url}?{payload}")
        response.raise_for_status()  # Raise HTTPError for bad responses
        return response.text
    except requests.RequestException as e:
        print(f"Request failed: {e}")
        return ""

# Advanced LFI detection
def advanced_lfi_detection(url):
    session = create_session()
    config = load_config('configs/lfi_config.json')

    for item in config:
        name = item.get('name')
        payload = item.get('payload')
        response_pattern = item.get('response')

        response = send_request(session, url, payload)
        if re.search(response_pattern, response):
            print(f"Parameter might be vulnerable to {name}")
            print(f"Payload: {payload}")
            break

def file_upload_vulnerability(url):
    try:
        page = requests.get(url)
        soup = BeautifulSoup(page.content, 'html.parser')
        inputs = soup.find_all('input', {'type': 'file'})
        
        if inputs:
            print("[+] File Upload Function available")
        else:
            print("[-] File Upload Function not found")
    except requests.RequestException as e:
        print(f"Error accessing {url}: {e}")

# Example usage
url = "https://vulnerable-website.com/"
advanced_lfi_detection(url)
file_upload_vulnerability(url)
