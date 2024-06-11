import requests
import re
import concurrent.futures
import random

def extractHeaders(headers_input):
    headers = {}
    if headers_input:
        header_lines = headers_input.split(';')
        for line in header_lines:
            key, value = line.split(':')
            headers[key.strip()] = value.strip()
    return headers

def requester(url, data, headers, get=True, timeout=0):
    if get:
        return requests.get(url, headers=headers, timeout=timeout)
    return requests.post(url, data=data, headers=headers, timeout=timeout)

def check_csrf(url, headers={}, delay=0, level=2, timeout=20, threads=2):
    try:
        # Phase 1: Crawling
        print('Phase: Crawling')
        response = requester(url, {}, headers)
        forms = re.findall(r'<form[^>]*action=["\'](.*?)["\']', response.text)
        print(f'Crawled {url} and found {len(forms)} form(s).')

        # Phase 2: Evaluating
        print('Phase: Evaluating')
        all_tokens = []
        for form_action in forms:
            response = requester(form_action, {}, headers)
            tokens = re.findall(r'<input[^>]+name=["\']csrf[^>]+>', response.text)
            if tokens:
                all_tokens.extend(tokens)
        print(f'Found {len(all_tokens)} CSRF token(s).')

        # Phase 3: Comparing
        print('Phase: Comparing')
        unique_tokens = set(all_tokens)
        if len(unique_tokens) < len(all_tokens):
            print('Potential Replay Attack condition found.')
            # Add further investigation logic here if needed

        # Phase 4: Observing
        print('Phase: Observing')
        sim_tokens = []
        for _ in range(100):
            good_token = random.choice(all_tokens)
            response = requester(url, {}, headers)
            tokens = re.findall(r'<input[^>]+name=["\']csrf[^>]+>', response.text)
            if tokens:
                sim_tokens.extend(tokens)
        if len(set(sim_tokens)) < len(sim_tokens):
            print('Same tokens were issued for simultaneous requests.')

        # Further phases can be added as needed

    except Exception as e:
        print('Error:', e)

if __name__ == "__main__":
    url = input("Enter the URL to check for CSRF vulnerability: ")
    check_csrf(url)
