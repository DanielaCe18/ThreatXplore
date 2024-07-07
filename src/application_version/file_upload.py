import requests
from bs4 import BeautifulSoup
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

def create_session():
    """
    Creates and configures a requests session with retry logic and custom headers.

    Args:
        None

    Returns:
        requests.Session: A configured session object.
    """
    session = requests.Session()
    retries = Retry(total=5, backoff_factor=0.1, status_forcelist=[500, 502, 503, 504])
    session.mount('http://', HTTPAdapter(max_retries=retries))
    session.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'})
    return session

def login(session, url, username, password):
    """
    Logs into the web application using the provided session.

    Args:
        session (requests.Session): The session to use for login.
        url (str): The base URL of the application.
        username (str): The username for login.
        password (str): The password for login.

    Returns:
        None
    """
    login_url = url + "/login.php"
    login_data = {
        'login': username,
        'password': password,
        'security_level': '0',
        'form': 'submit'
    }
    session.post(login_url, data=login_data)

def file_upload_vulnerability(session, url):
    """
    Checks if the given URL has a file upload vulnerability.

    Args:
        session (requests.Session): The session to use for making requests.
        url (str): The URL to check for file upload vulnerability.

    Returns:
        tuple: A tuple containing a boolean indicating if a vulnerability was found,
               and a string message with the details.
    """
    try:
        page = session.get(url)
        soup = BeautifulSoup(page.content, 'html.parser')
        
        forms = soup.find_all('form')
        for form in forms:
            if form.find('input', {'type': 'file'}):
                message = f"File Upload Function available at {url}"
                print(message)
                return True, message
        message = "No file upload function detected."
        print(message)
        return False, message
    except requests.RequestException as e:
        error_message = f"Error accessing {url}: {e}"
        print(error_message)
        return False, error_message

if __name__ == "__main__":
    base_url = "http://localhost/bWAPP"
    username = "bee"
    password = "bug"

    session = create_session()
    login(session, base_url, username, password)

    urlfile = base_url + "/unrestricted_file_upload.php"

    vulnerabilities_found, description = file_upload_vulnerability(session, urlfile)
    if vulnerabilities_found:
        print(f"{urlfile} is vulnerable to unrestricted file upload")
