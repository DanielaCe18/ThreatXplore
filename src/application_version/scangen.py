import requests
from bs4 import BeautifulSoup
import dns.resolver
import ssl
import socket
from urllib.parse import urlparse
from datetime import datetime

def get_domain_info(url):
    """
    Retrieves the domain name and IP addresses for the given URL.

    Args:
        url (str): The URL to retrieve domain information for.

    Returns:
        tuple: A tuple containing the domain name and a list of IP addresses.
    """
    domain = urlparse(url).netloc
    ips = dns.resolver.resolve(domain, 'A')
    ip_list = [ip.to_text() for ip in ips]
    return domain, ip_list

def get_http_https_transfers(url):
    """
    Retrieves the HTTP/HTTPS transfer history for the given URL.

    Args:
        url (str): The URL to check for HTTP/HTTPS transfers.

    Returns:
        list: A list of tuples containing the status code and URL for each transfer.
    """
    response = requests.get(url)
    if response.history:
        transfers = [(resp.status_code, resp.url) for resp in response.history]
        transfers.append((response.status_code, response.url))
    else:
        transfers = [(response.status_code, response.url)]
    return transfers

def get_all_page_links(url):
    """
    Retrieves all the links from the given URL's page.

    Args:
        url (str): The URL to retrieve links from.

    Returns:
        set: A set of URLs found on the page.
    """
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    links = {link.get('href') for link in soup.find_all('a', href=True)}
    return links

def get_cookies(url):
    """
    Retrieves the cookies set by the given URL.

    Args:
        url (str): The URL to retrieve cookies from.

    Returns:
        dict: A dictionary of cookies.
    """
    response = requests.get(url)
    return response.cookies.get_dict()

def get_headers(url):
    """
    Retrieves the HTTP headers from the given URL.

    Args:
        url (str): The URL to retrieve headers from.

    Returns:
        dict: A dictionary of headers.
    """
    response = requests.get(url)
    return response.headers

def get_certificate_info(url):
    """
    Retrieves the SSL certificate information for the given URL.

    Args:
        url (str): The URL to retrieve SSL certificate information for.

    Returns:
        dict: A dictionary of SSL certificate information.
    """
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
            # Converting notBefore and notAfter to datetime for better readability
            cert_info['notBefore'] = datetime.strptime(cert_info['notBefore'], '%b %d %H:%M:%S %Y %Z')
            cert_info['notAfter'] = datetime.strptime(cert_info['notAfter'], '%b %d %H:%M:%S %Y %Z')
    return cert_info

def get_outgoing_links(url):
    """
    Retrieves all outgoing links from the given URL's page.

    Args:
        url (str): The URL to retrieve outgoing links from.

    Returns:
        set: A set of outgoing URLs found on the page.
    """
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    outgoing_links = {link.get('href') for link in soup.find_all('a', href=True) if urlparse(link.get('href')).netloc != urlparse(url).netloc}
    return outgoing_links

def scan_general_info(url):
    """
    Scans the given URL for general information including domain info, HTTP/HTTPS transfers,
    page links, cookies, headers, SSL certificate info, and outgoing links.

    Args:
        url (str): The URL to scan.

    Returns:
        dict: A dictionary containing the scanned information.
    """
    info = {}
    
    domain, ips = get_domain_info(url)
    info['domain'] = domain
    info['ips'] = ips
    
    transfers = get_http_https_transfers(url)
    info['transfers'] = transfers
    
    links = get_all_page_links(url)
    info['links'] = links
    
    cookies = get_cookies(url)
    info['cookies'] = cookies
    
    headers = get_headers(url)
    info['headers'] = headers
    
    cert_info = get_certificate_info(url)
    info['cert_info'] = cert_info
    
    outgoing_links = get_outgoing_links(url)
    info['outgoing_links'] = outgoing_links
    
    return info

# No need for the main() function if we are using this as a module.
