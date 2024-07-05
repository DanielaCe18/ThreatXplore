import requests
from bs4 import BeautifulSoup
import dns.resolver
import ssl
import socket
from urllib.parse import urlparse
from datetime import datetime, timedelta

def resolve_domain_to_ip(domain):
    """
    Resolves a domain to its IP address.
    
    Args:
        domain (str): The domain to resolve.
    
    Returns:
        str: A formatted string with the domain and its resolved IP address or an error message.
    """
    try:
        ip_address = socket.gethostbyname(domain)
        result = f"Domain: {domain}\nIPs: {ip_address}\n"
        return result
    except socket.gaierror as e:
        error_message = f"Error resolving domain {domain}: {e}\n"
        return error_message

def get_http_https_transfers(url):
    """
    Retrieves the HTTP/HTTPS transfer history for a given URL.
    
    Args:
        url (str): The URL to check.
    
    Returns:
        str: A formatted string with the HTTP/HTTPS transfer history.
    """
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
    """
    Retrieves all links from a webpage.
    
    Args:
        url (str): The URL of the webpage to retrieve links from.
    
    Returns:
        str: A formatted string with all the links found on the page.
    """
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    links = {link.get('href') for link in soup.find_all('a', href=True)}
    links_formatted = "\n".join(links)
    result = f"All Page Links:\n{links_formatted}\n"
    return result

def get_cookies(url):
    """
    Retrieves cookies from a webpage.
    
    Args:
        url (str): The URL of the webpage to retrieve cookies from.
    
    Returns:
        str: A formatted string with the cookies found on the page.
    """
    response = requests.get(url)
    cookies = response.cookies.get_dict()
    cookies_formatted = "\n".join([f"{key}: {value}" for key, value in cookies.items()])
    result = f"Cookies:\n{cookies_formatted}\n"
    return result

def get_headers(url):
    """
    Retrieves headers from a webpage.
    
    Args:
        url (str): The URL of the webpage to retrieve headers from.
    
    Returns:
        str: A formatted string with the headers found on the page.
    """
    response = requests.get(url)
    headers = response.headers
    headers_formatted = "\n".join([f"{key}: {value}" for key, value in headers.items()])
    result = f"Headers:\n{headers_formatted}\n"
    return result

def get_certificate_info(url):
    """
    Retrieves SSL certificate information from a domain.
    
    Args:
        url (str): The URL of the webpage to retrieve the SSL certificate from.
    
    Returns:
        str: A formatted string with the SSL certificate information.
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
            cert_info['notBefore'] = datetime.strptime(cert_info['notBefore'], '%b %d %H:%M:%S %Y %Z')
            cert_info['notAfter'] = datetime.strptime(cert_info['notAfter'], '%b %d %H:%M:%S %Y %Z')
            cert_info_formatted = "\n".join([f"{key}: {value}" for key, value in cert_info.items()])
            result = f"Certificate Info:\n{cert_info_formatted}\n"
            return result

def get_outgoing_links(url):
    """
    Retrieves outgoing links from a webpage.
    
    Args:
        url (str): The URL of the webpage to retrieve outgoing links from.
    
    Returns:
        str: A formatted string with the outgoing links found on the page.
    """
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    outgoing_links = {link.get('href') for link in soup.find_all('a', href=True) if urlparse(link.get('href')).netloc != urlparse(url).netloc}
    outgoing_links_formatted = "\n".join(outgoing_links)
    result = f"Outgoing Links:\n{outgoing_links_formatted}\n"
    return result

def general_scan_url(url):
    """
    Performs a general scan of a given URL, retrieving various information.
    
    Args:
        url (str): The URL to scan.
    
    Returns:
        list: A list of results containing the information retrieved from the scan.
    """
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
