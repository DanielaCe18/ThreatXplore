import requests
import re

def find_emails(url):
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }
    try:
        response = requests.get(url, headers=headers, verify=True)
        response.raise_for_status()
        content = response.content.decode('utf-8')
        emails = re.findall(r'[\w.-]+@[\w.-]+\.\w+', content)
        return emails
    except requests.RequestException as e:
        print(f"Error accessing {url}: {e}")
        return []

def find_credit_cards(url):
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }
    credit_card_patterns = {
        'MASTERCARD': r"5[1-5][0-9]{14}",
        'VISA': r"4[0-9]{12}(?:[0-9]{3})?",
        'AMEX': r"3[47][0-9]{13}",
        'DISCOVER': r"6(?:011|5[0-9]{2})[0-9]{12}"
    }

    try:
        response = requests.get(url, headers=headers, verify=True)
        response.raise_for_status()
        content = response.content.decode('utf-8')
        content = ''.join(content.split())

        found_cards = []
        for card_type, pattern in credit_card_patterns.items():
            matches = re.findall(pattern, content)
            for match in matches:
                found_cards.append(f"[+] Website has a {card_type} card: {match}")
        return found_cards
    except requests.RequestException as e:
        print(f"Error accessing {url}: {e}")
        return []

if __name__ == "__main__":
    urlemail = "https://esgi.fr"  # Replace with the target URL
    results = find_emails(urlemail)
    for result in results:
        print(result)

    urlcard = "https://cyberini.com"
    results = find_credit_cards(urlcard)
    for result in results:
        print(result)
