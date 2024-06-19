import nmap
import json

def scan_ports(target, options):
    nm = nmap.PortScanner()
    nm.scan(target, arguments=options)
    return nm

def print_scan_results(nm, target):
    for host in nm.all_hosts():
        print(f"Host : {host} ({nm[host].hostname()})")
        print(f"State : {nm[host].state()}")
        for proto in nm[host].all_protocols():
            print("----------")
            print(f"Protocol : {proto}")

            lport = nm[host][proto].keys()
            for port in lport:
                print(f"Port : {port}\tState : {nm[host][proto][port]['state']}")
                if 'product' in nm[host][proto][port]:
                    print(f"Service : {nm[host][proto][port]['product']}")
                if 'version' in nm[host][proto][port]:
                    print(f"Version : {nm[host][proto][port]['version']}")
                if 'script' in nm[host][proto][port]:
                    print(f"Script : {json.dumps(nm[host][proto][port]['script'])}")

if __name__ == "__main__":
    target = input("Enter the target URL or IP address: ")
    options = "-sS -sV -O -p- --script=vuln"
    nm = scan_ports(target, options)
    print_scan_results(nm, target)
