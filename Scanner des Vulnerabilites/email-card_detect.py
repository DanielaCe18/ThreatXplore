import requests
import re

def find_emails(url):
    try:
        response = requests.get(url, verify=False)
        response.raise_for_status()  # Check for request errors
        content = response.content.decode('utf-8')  # Decode content to string
        emails = re.findall(r'[\w.-]+@[\w.-]+\.\w+', content)
        for email in emails:
            print("[+] E-mail: ", email)
    except requests.RequestException as e:
        print(f"Error accessing {url}: {e}")

def find_credit_cards(url):
    credit_card_patterns = {
        'MASTERCARD': r"5[1-5][0-9]{14}",
        'VISA': r"4[0-9]{12}(?:[0-9]{3})?",
        'AMEX': r"3[47][0-9]{13}",
        'DISCOVER': r"6(?:011|5[0-9]{2})[0-9]{12}"
    }

    try:
        response = requests.get(url, verify=False)
        response.raise_for_status()  # Check for request errors
        content = response.content.decode('utf-8')  # Decode content to string
        content = ''.join(content.split())  # Remove whitespace

        for card_type, pattern in credit_card_patterns.items():
            matches = re.findall(pattern, content)
            if matches:
                for match in matches:
                    print(f"[+] Website has a {card_type} card: {match}")
            else:
                print(f"[-] Website doesn't have a {card_type} card.")
    except requests.RequestException as e:
        print(f"Error accessing {url}: {e}")

# Example usage
url = "https://www.cdiscount.com/"
find_emails(url)
find_credit_cards(url)
