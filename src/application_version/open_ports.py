import nmap
import json

def scan_ports(target, options):
    """
    Scans the target for open ports and services using nmap with the given options.

    Args:
        target (str): The IP address or hostname of the target to scan.
        options (str): The options to pass to nmap for the scan.

    Returns:
        nmap.PortScanner: An nmap scanner object containing the scan results.
    """
    nm = nmap.PortScanner()
    nm.scan(target, arguments=options)
    return nm

def get_scan_results(nm):
    """
    Extracts and formats the scan results from the nmap scanner object.

    Args:
        nm (nmap.PortScanner): The nmap scanner object containing the scan results.

    Returns:
        list: A list of dictionaries with formatted scan results for each host.
    """
    results = []
    for host in nm.all_hosts():
        host_info = {
            "host": host,
            "hostname": nm[host].hostname(),
            "state": nm[host].state(),
            "protocols": []
        }
        for proto in nm[host].all_protocols():
            proto_info = {
                "protocol": proto,
                "ports": []
            }
            lport = nm[host][proto].keys()
            for port in lport:
                port_info = {
                    "port": port,
                    "state": nm[host][proto][port]['state'],
                    "service": nm[host][proto][port].get('product', ''),
                    "version": nm[host][proto][port].get('version', ''),
                    "script": json.dumps(nm[host][proto][port].get('script', {}))
                }
                proto_info["ports"].append(port_info)
            host_info["protocols"].append(proto_info)
        results.append(host_info)
    return results

def main():
    target = "127.0.0.1"
    options = "-sV"  # Example options for nmap scan
    
    nm = scan_ports(target, options)
    scan_results = get_scan_results(nm)
    
    print(json.dumps(scan_results, indent=4))

if __name__ == "__main__":
    main()
