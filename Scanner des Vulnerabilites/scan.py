import requests
from bs4 import BeautifulSoup
import dns.resolver
from scapy.all import *
import ssl
import socket
from urllib.parse import urlparse

def get_domain_info(url):
    domain = urlparse(url).netloc
    ips = dns.resolver.resolve(domain, 'A')
    ip_list = [ip.to_text() for ip in ips]
    return domain, ip_list

def get_http_https_transfers(url):
    response = requests.get(url)
    if response.history:
        transfers = [(resp.status_code, resp.url) for resp in response.history]
        transfers.append((response.status_code, response.url))
    else:
        transfers = [(response.status_code, response.url)]
    return transfers

def get_all_page_links(url):
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    links = {link.get('href') for link in soup.find_all('a', href=True)}
    return links

def get_cookies(url):
    response = requests.get(url)
    return response.cookies.get_dict()

def get_headers(url):
    response = requests.get(url)
    return response.headers

def get_certificate_info(url):
    domain = urlparse(url).netloc
    context = ssl.create_default_context()
    with socket.create_connection((domain, 443)) as sock:
        with context.wrap_socket(sock, server_hostname=domain) as ssock:
            cert = ssock.getpeercert()
    return cert

def get_outgoing_links(url):
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    outgoing_links = {link.get('href') for link in soup.find_all('a', href=True) if urlparse(link.get('href')).netloc != urlparse(url).netloc}
    return outgoing_links

def main():
    url = input("Enter the URL: ")
    print("Gathering information for:", url)
    
    domain, ips = get_domain_info(url)
    print("Domain:", domain)
    print("IPs:", ips)
    
    transfers = get_http_https_transfers(url)
    print("HTTP/HTTPS Transfers:", transfers)
    
    links = get_all_page_links(url)
    print("All Page Links:", links)
    
    cookies = get_cookies(url)
    print("Cookies:", cookies)
    
    headers = get_headers(url)
    print("Headers:", headers)
    
    cert_info = get_certificate_info(url)
    print("Certificate Info:", cert_info)
    
    outgoing_links = get_outgoing_links(url)
    print("Outgoing Links:", outgoing_links)

if __name__ == "__main__":
    main()
