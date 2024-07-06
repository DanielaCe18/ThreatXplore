import nmap
import json

def scan_ports(target, options):
    nm = nmap.PortScanner()
    nm.scan(target, arguments=options)
    return nm

def get_scan_results(nm):
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
