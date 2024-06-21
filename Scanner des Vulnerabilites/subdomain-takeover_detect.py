#!/usr/bin/env python

import re
import sys
import requests
from urllib.parse import urlsplit
from time import sleep

# Expanded common services with their potential takeover error messages and status codes
services = {
    'AWS/S3': {'code': '[300-499]', 'error': r'The specified bucket does not exist'},
    'BitBucket': {'code': '[300-499]', 'error': r'Repository not found'},
    'CloudFront': {'code': '[300-499]', 'error': r'ERROR\: The request could not be satisfied'},
    'Github': {'code': '[300-499]', 'error': r'There isn\'t a Github Pages site here\.'},
    'Shopify': {'code': '[300-499]', 'error': r'Sorry\, this shop is currently unavailable\.'},
    'Desk': {'code': '[300-499]', 'error': r'Sorry\, We Couldn\'t Find That Page'},
    'Fastly': {'code': '[300-499]', 'error': r'Fastly error\: unknown domain\:'},
    'FeedPress': {'code': '[300-499]', 'error': r'The feed has not been found\.'},
    'Ghost': {'code': '[300-499]', 'error': r'The thing you were looking for is no longer here\, or never was'},
    # Add more services here
}

def request(url):
    headers = {'User-Agent': 'Mozilla/5.0'}
    try:
        requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
        response = requests.get(url=url, headers=headers, timeout=10)
        return response.status_code, response.content, response.headers
    except requests.exceptions.RequestException as e:
        print(f"[!] Error: {e}")
    return None, None, None

def checker(status, content, headers):
    for service, values in services.items():
        if re.search(values['code'], str(status), re.I) and re.search(values['error'], str(content), re.I):
            return service, values['error']
        # Additional checks can be added here based on headers or other response attributes
    return None, None

def check_url(url):
    o = urlsplit(url)
    if o.scheme not in ['http', 'https', '']:
        print(f"[!] Scheme {o.scheme} not supported!!")
        sys.exit()
    if o.netloc == '':
        return 'http://' + o.path
    elif o.netloc:
        return o.scheme + '://' + o.netloc
    else:
        return 'http://' + o.netloc

def get_subdomains(domain):
    subdomains = []
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            for entry in data:
                name_value = entry['name_value']
                for subdomain in name_value.split('\n'):
                    if subdomain not in subdomains:
                        subdomains.append(subdomain)
    except requests.exceptions.RequestException as e:
        print(f"[!] Error fetching subdomains: {e}")
    return subdomains

def main(domain):
    print(f"[+] Enumerating subdomains for {domain}...")
    subdomains = get_subdomains(domain)
    if not subdomains:
        print("[!] No subdomains found.")
        return
    
    print(f"[+] Found {len(subdomains)} subdomains.")
    print("[+] Starting scanning for potential takeover vulnerabilities...")
    
    for subdomain in subdomains:
        target_url = check_url(f"http://{subdomain}")
        print(f"[+] Checking {target_url}...")
        status, content, headers = request(target_url)
        if status and content:
            service, error = checker(status, content, headers)
            if service and error:
                print(f"[+] Found service: {service}")
                print(f"[+] A potential TAKEOVER vulnerability found on {target_url}!")
            else:
                print(f"[+] No takeover vulnerability found on {target_url}.")
        else:
            print(f"[!] Failed to retrieve the target URL: {target_url}")
        sleep(1)  # Adding delay between requests to avoid rate limiting

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python takeover.py <domain>")
        sys.exit()
    domain = sys.argv[1]
    main(domain)
