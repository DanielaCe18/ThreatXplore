import requests
from bs4 import BeautifulSoup
import dns.resolver
import ssl
import socket
from urllib.parse import urlparse
from datetime import datetime, timedelta

def resolve_domain_to_ip(domain):
    try:
        ip_address = socket.gethostbyname(domain)
        result = f"Domain: {domain}\nIPs: {ip_address}\n"
        return result
    except socket.gaierror as e:
        error_message = f"Error resolving domain {domain}: {e}\n"
        return error_message

def get_http_https_transfers(url):
    response = requests.get(url)
    if response.history:
        transfers = [(resp.status_code, resp.url) for resp in response.history]
        transfers.append((response.status_code, response.url))
    else:
        transfers = [(response.status_code, response.url)]
    transfers_formatted = "\n".join([f"Status Code: {code}, URL: {url}" for code, url in transfers])
    result = f"HTTP/HTTPS Transfers:\n{transfers_formatted}\n"
    return result

def get_all_page_links(url):
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    links = {link.get('href') for link in soup.find_all('a', href=True)}
    links_formatted = "\n".join(links)
    result = f"All Page Links:\n{links_formatted}\n"
    return result

def get_cookies(url):
    response = requests.get(url)
    cookies = response.cookies.get_dict()
    cookies_formatted = "\n".join([f"{key}: {value}" for key, value in cookies.items()])
    result = f"Cookies:\n{cookies_formatted}\n"
    return result

def get_headers(url):
    response = requests.get(url)
    headers = response.headers
    headers_formatted = "\n".join([f"{key}: {value}" for key, value in headers.items()])
    result = f"Headers:\n{headers_formatted}\n"
    return result

def get_certificate_info(url):
    domain = urlparse(url).netloc
    context = ssl.create_default_context()
    with socket.create_connection((domain, 443)) as sock:
        with context.wrap_socket(sock, server_hostname=domain) as ssock:
            cert = ssock.getpeercert()
            cert_info = {
                'issuer': dict(x[0] for x in cert['issuer']),
                'subject': dict(x[0] for x in cert['subject']),
                'serialNumber': cert['serialNumber'],
                'version': cert['version'],
                'notBefore': cert['notBefore'],
                'notAfter': cert['notAfter'],
                'subjectAltName': cert['subjectAltName']
            }
            cert_info['notBefore'] = datetime.strptime(cert_info['notBefore'], '%b %d %H:%M:%S %Y %Z')
            cert_info['notAfter'] = datetime.strptime(cert_info['notAfter'], '%b %d %H:%M:%S %Y %Z')
            cert_info_formatted = "\n".join([f"{key}: {value}" for key, value in cert_info.items()])
            result = f"Certificate Info:\n{cert_info_formatted}\n"
            return result

def get_outgoing_links(url):
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    outgoing_links = {link.get('href') for link in soup.find_all('a', href=True) if urlparse(link.get('href')).netloc != urlparse(url).netloc}
    outgoing_links_formatted = "\n".join(outgoing_links)
    result = f"Outgoing Links:\n{outgoing_links_formatted}\n"
    return result

def general_scan_url(url):
    results = []
    domain = urlparse(url).netloc
    results.append(resolve_domain_to_ip(domain))
    results.append(get_http_https_transfers(url))
    results.append(get_all_page_links(url))
    results.append(get_cookies(url))
    results.append(get_headers(url))
    results.append(get_certificate_info(url))
    results.append(get_outgoing_links(url))
    return results

if __name__ == "__main__":
    target_url = input("Enter the URL: ")
    results = general_scan_url(target_url)
    for result in results:
        print(result)
