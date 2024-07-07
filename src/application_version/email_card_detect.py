import requests
import re

def find_emails(url):
    """
    Finds and prints email addresses from the content of the given URL.

    Args:
        url (str): The URL to fetch and search for email addresses.

    Returns:
        None
    """
    try:
        response = requests.get(url, verify=True)  # Default behavior
        response.raise_for_status()  # Check for request errors
        content = response.content.decode('utf-8')  # Decode content to string
        emails = re.findall(r'[\w.-]+@[\w.-]+\.\w+', content)
        for email in emails:
            print("[+] E-mail: ", email)
    except requests.RequestException as e:
        print(f"Error accessing {url}: {e}")

def find_credit_cards(url):
    """
    Finds and returns credit card numbers from the content of the given URL.

    Args:
        url (str): The URL to fetch and search for credit card numbers.

    Returns:
        list: A list of strings containing messages about found or not found credit card numbers.
    """
    credit_card_patterns = {
        'MASTERCARD': r"5[1-5][0-9]{14}",
        'VISA': r"4[0-9]{12}(?:[0-9]{3})?",
        'AMEX': r"3[47][0-9]{13}",
        'DISCOVER': r"6(?:011|5[0-9]{2})[0-9]{12}"
    }

    results = []

    try:
        response = requests.get(url, verify=True)  # Default behavior
        response.raise_for_status()  # Check for request errors
        content = response.content.decode('utf-8')  # Decode content to string
        content = ''.join(content.split())  # Remove whitespace

        for card_type, pattern in credit_card_patterns.items():
            matches = re.findall(pattern, content)
            if matches:
                for match in matches:
                    results.append(f"[+] Website has a {card_type} card: {match}")
            else:
                results.append(f"[-] Website doesn't have a {card_type} card.")
    except requests.RequestException as e:
        results.append(f"Error accessing {url}: {e}")

    return results

def main():
    """
    Main function to demonstrate the usage of find_emails and find_credit_cards functions.

    Args:
        None

    Returns:
        None
    """
    url = "https://vulnerable-website.com/catalog/cart"
    find_emails(url)
    results = find_credit_cards(url)
    for result in results:
        print(result)

if __name__ == "__main__":
    main()
