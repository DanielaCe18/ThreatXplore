import requests
import time
import asyncio
import aiohttp
import nmap
from concurrent.futures import ThreadPoolExecutor

# Function for port scanning with version detection
def scan_ports(target):
    nm = nmap.PortScanner()
    nm.scan(target, '1-1024', arguments='-sV')
    open_ports = []
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            lport = nm[host][proto].keys()
            for port in lport:
                service = nm[host][proto][port]['product']
                version = nm[host][proto][port]['version']
                state = nm[host][proto][port]['state']
                if state == 'open':
                    open_ports.append((port, service, version))
    return open_ports

# Function to simulate HTTP flooding with randomized headers
def http_flood(url, num_requests):
    headers = [
        {'User-Agent': 'Mozilla/5.0', 'Accept': 'text/html'},
        {'User-Agent': 'curl/7.68.0', 'Accept': '*/*'},
        {'User-Agent': 'PostmanRuntime/7.26.8', 'Accept': '*/*'},
        # Add more headers as needed
    ]
    for i in range(num_requests):
        try:
            response = requests.get(url, headers=headers[i % len(headers)])
            print(f"Request {i+1}: Status Code {response.status_code}")
        except requests.exceptions.RequestException as e:
            print(f"Request {i+1} failed: {e}")
        time.sleep(0.1)  # Adjust the sleep time as needed

# Function to simulate resource exhaustion with complex payloads
async def fetch(session, url, payload):
    try:
        async with session.post(url, json=payload) as response:
            return await response.text()
    except Exception as e:
        print(f"Request failed: {e}")

async def resource_exhaustion_async(url, num_requests):
    payload = {'data': 'x' * 10000}  # Large payload for testing
    async with aiohttp.ClientSession() as session:
        tasks = [fetch(session, url, payload) for _ in range(num_requests)]
        responses = await asyncio.gather(*tasks)

# Function to check rate limiting with gradual increase
def check_rate_limiting(url, max_requests, step):
    for i in range(1, max_requests + 1, step):
        print(f"\n--- Sending {i} requests ---")
        with ThreadPoolExecutor(max_workers=i) as executor:
            futures = [executor.submit(requests.get, url) for _ in range(i)]
            for future in futures:
                try:
                    response = future.result()
                    print(f"Status Code: {response.status_code}")
                except requests.exceptions.RequestException as e:
                    print(f"Request failed: {e}")
        time.sleep(1)  # Pause between bursts

# Main function
def main():
    target = input("Enter the target URL (e.g., http://example.com): ")
    
    # Initial Reconnaissance
    print("\n--- Port Scanning ---")
    open_ports = scan_ports(target)
    if open_ports:
        for port, service, version in open_ports:
            print(f"Open port: {port}, Service: {service}, Version: {version}")
    else:
        print("No open ports found.")
    
    # Simulate DoS Scenarios
    print("\n--- HTTP Flooding ---")
    http_flood(target, 50)  # Number of requests can be adjusted

    print("\n--- Resource Exhaustion ---")
    asyncio.run(resource_exhaustion_async(target, 50))  # Number of requests can be adjusted

    # Detect Vulnerability Indicators
    print("\n--- Checking Rate Limiting ---")
    check_rate_limiting(target, 20, 5)  # Max requests and step can be adjusted

if __name__ == "__main__":
    main()
