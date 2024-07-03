import nmap
import json
import socket
from urllib.parse import urlparse

def resolve_domain_to_ip(domain):
    try:
        ip_address = socket.gethostbyname(domain)
        return ip_address
    except socket.gaierror as e:
        print(f"Error resolving domain {domain}: {e}")
        return None

def scan_ports(target, options):
    nm = nmap.PortScanner()
    nm.scan(target, arguments=options)
    return nm

def collect_scan_results(nm):
    results = []
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
    return results

if __name__ == "__main__":
    target_url = input('Enter the URL to test for CORS vulnerability: ')
    
    parsed_url = urlparse(target_url)
    domain = parsed_url.hostname
    
    ip_address = resolve_domain_to_ip(domain)
    
    if ip_address:
        print(f"Resolved IP address of {domain} is {ip_address}")
        options = "-sS -sV -O -p- --script=vuln"
        nm = scan_ports(ip_address, options)
        scan_results = collect_scan_results(nm)
        
        for result in scan_results:
            print(json.dumps(result, indent=2))
    else:
        print("Failed to resolve domain to an IP address.")
