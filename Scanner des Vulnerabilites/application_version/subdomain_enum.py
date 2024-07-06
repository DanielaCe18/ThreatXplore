import re
import sys
import requests
import dns.resolver
import concurrent.futures
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
    'Heroku': {'code': '[300-499]', 'error': r'No such app'},
    'Pantheon': {'code': '[300-499]', 'error': r'The site you were looking for couldn\'t be found'},
    'Tumblr': {'code': '[300-499]', 'error': r'Whatever you were looking for doesn\'t currently exist at this address'},
    # Add more services here
}

def request(url, retries=1, timeout=5):
    headers = {'User-Agent': 'Mozilla/5.0'}
    for attempt in range(retries):
        try:
            requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
            response = requests.get(url=url, headers=headers, timeout=timeout)
            return response.status_code, response.content, response.headers
        except requests.exceptions.RequestException:
            sleep(1)  # Wait before retrying
    return None, None, None

def checker(status, content, headers):
    for service, values in services.items():
        if re.search(values['code'], str(status), re.I) and re.search(values['error'], str(content), re.I):
            return service
    return None

def check_url(url):
    o = urlsplit(url)
    if o.scheme not in ['http', 'https', '']:
        sys.exit()
    if o.netloc == '':
        return 'http://' + o.path
    elif o.netloc:
        return o.scheme + '://' + o.netloc
    else:
        return 'http://' + o.netloc

def get_subdomains(domain):
    subdomains = []
    # crt.sh method
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
    except requests.exceptions.RequestException:
        pass

    # DNS enumeration
    try:
        result = dns.resolver.resolve(f'*.{domain}', 'CNAME')
        for cname in result:
            subdomains.append(cname.to_text())
    except Exception:
        pass

    return subdomains

def scan_subdomain(subdomain):
    target_urls = [check_url(f"http://{subdomain}"), check_url(f"https://{subdomain}")]
    for target_url in target_urls:
        status, content, headers = request(target_url)
        if status and content:
            service = checker(status, content, headers)
            if service:
                return target_url, service
    return None

def main():
    url = "http://portswigger-labs.net"
    domain = urlsplit(url).netloc

    subdomains = get_subdomains(domain)
    if not subdomains:
        print("[!] No subdomains found.")
        return

    print(f"[+] Found {len(subdomains)} subdomains:")
    for subdomain in subdomains:
        print(subdomain)

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        future_to_subdomain = {executor.submit(scan_subdomain, subdomain): subdomain for subdomain in subdomains}
        for future in concurrent.futures.as_completed(future_to_subdomain):
            try:
                result = future.result()
                if result:
                    target_url, service = result
                    results.append((target_url, service))
            except Exception as e:
                print(f"[!] Error during scan: {e}")

    if not results:
        print("[+] No vulnerabilities found.")
    else:
        print("[+] Vulnerabilities found:")
        for result in results:
            print(f"{result[0]} - Service: {result[1]}")

if __name__ == "__main__":
    main()
