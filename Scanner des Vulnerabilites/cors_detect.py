import requests

# Global settings for the requests
proxies = None
allow_redirects = True
verify = True
cookies = {}

# Define logging functions
def log_info(message):
    print(f"{message}")

def log_vulnerability(message):
    print(f"{message}")

# Function to extract the domain from a URL
def extract_domain(site):
    if site.startswith("http://"):
        return site[7:]
    elif site.startswith("https://"):
        return site[8:]
    return site

# Main CORS vulnerability scan function
def cors_scan(site):
    domain = extract_domain(site)
    
    # Test for Basic Origin reflection payload
    log_info("Testing for Basic Origin reflection payload")
    response = requests.get(site, headers={"Origin": "https://evil.com"}, proxies=proxies, allow_redirects=allow_redirects, verify=verify, cookies=cookies)
    if "https://evil.com" in response.headers.get("Access-Control-Allow-Origin", ""):
        log_vulnerability("Website is vulnerable to Basic Origin Reflection payload")
    
    # Test for Trusted null Origin payload
    log_info("Testing for Trusted null Origin payload")
    response = requests.get(site, headers={"Origin": "null"}, proxies=proxies, allow_redirects=allow_redirects, verify=verify, cookies=cookies)
    if "null" in response.headers.get("Access-Control-Allow-Origin", ""):
        log_vulnerability("Website is vulnerable to Trusted null Origin payload")

    # Test for Whitelisted null origin value payload
    log_info("Testing for Whitelisted null origin value payload")
    response = requests.get(site, headers={"Origin": "null"}, proxies=proxies, allow_redirects=allow_redirects, verify=verify, cookies=cookies)
    if "null" in response.headers.get("Access-Control-Allow-Origin", ""):
        log_vulnerability("Website is vulnerable to Whitelisted null origin value payload")
    
    # Test for Trusted subdomain in Origin payload
    log_info("Testing for Trusted subdomain in Origin payload")
    response = requests.get(site, headers={"Origin": f"evil.{domain}"}, proxies=proxies, allow_redirects=allow_redirects, verify=verify, cookies=cookies)
    if f"evil.{domain}" in response.headers.get("Access-Control-Allow-Origin", ""):
        log_vulnerability("Website is vulnerable to Trusted subdomain in Origin payload")

    # Test for abuse on not properly Domain validation
    log_info("Testing for abuse on not properly Domain validation")
    response = requests.get(site, headers={"Origin": f"evil{domain}"}, proxies=proxies, allow_redirects=allow_redirects, verify=verify, cookies=cookies)
    if f"evil{domain}" in response.headers.get("Access-Control-Allow-Origin", ""):
        log_vulnerability("Website is vulnerable to abuse on not properly Domain validation")

    # Test for Origin domain extension not validated vulnerability
    log_info("Testing for Origin domain extension not validated vulnerability")
    response = requests.get(site, headers={"Origin": f"{domain}.evil.com"}, proxies=proxies, allow_redirects=allow_redirects, verify=verify, cookies=cookies)
    if f"{domain}.evil.com" in response.headers.get("Access-Control-Allow-Origin", ""):
        log_vulnerability("Website is vulnerable to Origin domain extension not validated vulnerability")
    
    # Test for Advanced CORS Bypassing using special characters
    chars = ["!", "(", ")", "'", ";", "=", "^", "{", "}", "|", "~", '"', '`', ",", "%60", "%0b"]
    for char in chars:
        log_info(f"Testing for Advanced CORS Bypassing using {char}")
        response = requests.get(site, headers={"Origin": f"{domain}{char}.evil.com"}, proxies=proxies, allow_redirects=allow_redirects, verify=verify, cookies=cookies)
        if f"{domain}{char}.evil.com" in response.headers.get("Access-Control-Allow-Origin", ""):
            log_vulnerability(f"Website is vulnerable to Advanced CORS Bypassing using special characters: {char}")

# Example usage
site = "http://testphp.vulnweb.com/artists.php?artist=1"
cors_scan(site)
