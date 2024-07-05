import nmap
import json
import socket
import subprocess
from urllib.parse import urlparse

def resolve_domain_to_ip(domain):
    """
    Resolves a domain to its IP address.
    
    Args:
        domain (str): The domain to resolve.
    
    Returns:
        str: The resolved IP address, or None if resolution fails.
    """
    try:
        ip_address = socket.gethostbyname(domain)
        return ip_address
    except socket.gaierror as e:
        print(f"Error resolving domain {domain}: {e}")
        return None

def scan_ports(target, options, timeout=10):
    """
    Scans ports on a target using nmap with specified options.
    
    Args:
        target (str): The target IP address or domain to scan.
        options (str): The nmap options for the scan.
        timeout (int, optional): The timeout for the scan in seconds.
    
    Returns:
        nmap.PortScanner: The scan results, or None if the scan times out.
    """
    nm = nmap.PortScanner()
    try:
        result = subprocess.run(['nmap', target] + options.split(), capture_output=True, text=True, timeout=timeout)
        nm.analyse_nmap_xml_scan(result.stdout)
        return nm
    except subprocess.TimeoutExpired:
        return None

def collect_scan_results(nm):
    """
    Collects and formats scan results from nmap.
    
    Args:
        nm (nmap.PortScanner): The nmap scan results.
    
    Returns:
        list: A list of formatted scan results.
    """
    results = []
    if not nm:
        print("No open ports found")
        return results

    for host in nm.all_hosts():
        result = {
            'Host': host,
            'Hostname': nm[host].hostname(),
            'State': nm[host].state(),
            'Protocols': []
        }
        for proto in nm[host].all_protocols():
            proto_info = {
                'Protocol': proto,
                'Ports': []
            }
            lport = nm[host][proto].keys()
            for port in lport:
                port_info = {
                    'Port': port,
                    'State': nm[host][proto][port]['state']
                }
                if 'product' in nm[host][proto][port]:
                    port_info['Service'] = nm[host][proto][port]['product']
                if 'version' in nm[host][proto][port]:
                    port_info['Version'] = nm[host][proto][port]['version']
                if 'script' in nm[host][proto][port]:
                    port_info['Script'] = json.dumps(nm[host][proto][port]['script'])
                proto_info['Ports'].append(port_info)
            result['Protocols'].append(proto_info)
        results.append(result)

    if not results:
        print("No open ports found")
        
    return results

if __name__ == "__main__":
    target_url = input("Enter the URL to scan: ")
    
    parsed_url = urlparse(target_url)
    domain = parsed_url.hostname
    
    ip_address = resolve_domain_to_ip(domain)
    
    if ip_address:
        options = "-sS -sV -O -p- --script=vuln"
        nm = scan_ports(ip_address, options)
        scan_results = collect_scan_results(nm)
        
        for result in scan_results:
            print(json.dumps(result, indent=2))
    else:
        print("Failed to resolve domain to an IP address.")
