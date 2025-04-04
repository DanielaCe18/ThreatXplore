from bs4 import BeautifulSoup
import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

def create_session():
    """
    Creates a requests session with a retry strategy.
    
    Returns:
        requests.Session: A session object configured with retries and headers.
    """
    session = requests.Session()
    retries = Retry(total=5, backoff_factor=0.1, status_forcelist=[500, 502, 503, 504])
    session.mount('http://', HTTPAdapter(max_retries=retries))
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'
    })
    return session

def login(session, url, username, password):
    """
    Logs into a website using the provided session, URL, username, and password.
    
    Args:
        session (requests.Session): The session object to use for the login.
        url (str): The base URL of the website.
        username (str): The username for login.
        password (str): The password for login.
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
    Checks for a file upload vulnerability on the specified URL.
    
    Args:
        session (requests.Session): The session object to use for the request.
        url (str): The URL to check for the file upload vulnerability.
    
    Returns:
        str: A message indicating whether a file upload function is available and the result of the attempt.
    """
    try:
        page = session.get(url)
        soup = BeautifulSoup(page.content, 'html.parser')
        
        forms = soup.find_all('form')
        for form in forms:
            if form.find('input', {'type': 'file'}):
                payload = {'file': ('test.txt', 'This is a test file.', 'text/plain')}
                response = session.post(url, files=payload)
                if response.status_code == 200:
                    return f"File Upload Function available at {url}\nPayload used: {payload}"
                else:
                    return f"File upload attempt failed at {url} with status code: {response.status_code}"
        return f"No file upload function found at {url}"
    except requests.RequestException as e:
        return f"Error accessing {url}: {e}"

def check_and_exploit_file_upload(target_url):
    """
    Checks and exploits a file upload vulnerability on the target URL.
    
    Args:
        target_url (str): The base URL of the target website.
    
    Returns:
        list: A list of results indicating the outcome of the vulnerability check and exploitation attempt.
    """
    username = "bee"
    password = "bug"
    base_url = target_url

    session = create_session()
    login(session, base_url, username, password)
    urlfile = base_url + "/unrestricted_file_upload.php"
    
    results = []
    result = file_upload_vulnerability(session, urlfile)
    results.append(result)
    return results

if __name__ == "__main__":
    target_url = input('Enter the URL to test for file upload vulnerability: ')
    results = check_and_exploit_file_upload(target_url)
    for result in results:
        print(result)
