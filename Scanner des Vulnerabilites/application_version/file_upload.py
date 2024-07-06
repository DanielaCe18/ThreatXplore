from bs4 import BeautifulSoup
import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

# Function to create a requests session with retry strategy
def create_session():
    session = requests.Session()
    retries = Retry(total=5, backoff_factor=0.1, status_forcelist=[500, 502, 503, 504])
    session.mount('http://', HTTPAdapter(max_retries=retries))
    session.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'})
    return session

# Function to login and create a session
def login(session, url, username, password):
    login_url = url + "/login.php"
    login_data = {
        'login': username,
        'password': password,
        'security_level': '0',
        'form': 'submit'
    }
    session.post(login_url, data=login_data)

def file_upload_vulnerability(session, url):
    try:
        page = session.get(url)
        soup = BeautifulSoup(page.content, 'html.parser')
        
        forms = soup.find_all('form')
        for form in forms:
            if form.find('input', {'type': 'file'}):
                print(f"[+] File Upload Function available at {url}")
                return True, "File upload function detected."
        return False, "No file upload function detected."
    except requests.RequestException as e:
        print(f"Error accessing {url}: {e}")
        return False, f"Error accessing {url}: {e}"

# Example usage
if __name__ == "__main__":
    base_url = "http://localhost/bWAPP"
    username = "bee"
    password = "bug"

    session = create_session()
    login(session, base_url, username, password)

    urlfile = base_url + "/unrestricted_file_upload.php"

    if file_upload_vulnerability(session, urlfile):
        print(f"{urlfile} is vulnerable to unrestricted file upload")
