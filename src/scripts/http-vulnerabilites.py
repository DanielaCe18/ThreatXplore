import requests

def check_uncommon_http_methods(url):
    uncommon_methods = ['OPTIONS', 'TRACE', 'CONNECT', 'PUT', 'DELETE']
    results = {}

    for method in uncommon_methods:
        try:
            response = requests.request(method, url)
            status_code = response.status_code
            headers = response.headers
            body = response.text[:500]  # Limit body to first 500 chars for brevity
            
            if status_code not in [405, 501]:
                results[method] = {
                    'status_code': status_code,
                    'headers': headers,
                    'body': body,
                    'vulnerability': True,
                    'reason': f'{method} method is allowed with status code {status_code}.'
                }
            else:
                results[method] = {
                    'status_code': status_code,
                    'vulnerability': False,
                    'reason': 'Method Not Allowed or Not Implemented.'
                }
        except Exception as e:
            results[method] = {'error': str(e), 'vulnerability': True, 'reason': 'Exception occurred.'}

    return results

def check_redirections(url):
    try:
        response = requests.get(url, allow_redirects=False)
        if response.is_redirect:
            return {
                'vulnerability': True,
                'status_code': response.status_code,
                'location': response.headers.get('Location', ''),
                'reason': f'Redirects to: {response.headers.get("Location", "")}'
            }
        else:
            return {'vulnerability': False, 'reason': 'No redirection detected.'}
    except Exception as e:
        return {'vulnerability': True, 'error': str(e), 'reason': 'Exception occurred.'}

def check_security_headers(url):
    required_headers = [
        'Content-Security-Policy',
        'X-Content-Type-Options',
        'X-Frame-Options',
        'Strict-Transport-Security',
        'X-XSS-Protection'
    ]
    
    try:
        response = requests.get(url)
        headers = response.headers
        missing_headers = [header for header in required_headers if header not in headers]
        
        if missing_headers:
            return {
                'vulnerability': True,
                'missing_headers': missing_headers,
                'reason': f'Missing security headers: {", ".join(missing_headers)}'
            }
        else:
            return {'vulnerability': False, 'reason': 'All required security headers are present.'}
    except Exception as e:
        return {'vulnerability': True, 'error': str(e), 'reason': 'Exception occurred.'}

def scan_url(url):
    print(f'Scanning URL: {url}')
    
    # Checking for uncommon HTTP methods
    print('\nChecking for uncommon HTTP methods...')
    methods_results = check_uncommon_http_methods(url)
    for method, result in methods_results.items():
        print(f'\nMethod: {method}')
        if 'error' in result:
            print(f"Error: {result['error']}")
        else:
            print(f"Status Code: {result['status_code']}")
            if result['vulnerability']:
                print("Potential Vulnerability Detected!")
            print(f"Reason: {result['reason']}")
            if 'headers' in result:
                print(f"Headers: {result['headers']}")
            if 'body' in result:
                print(f"Body: {result['body']}")
    
    # Checking for HTTP redirections
    print('\nChecking for HTTP redirections...')
    redirection_result = check_redirections(url)
    if 'error' in redirection_result:
        print(f"Error: {redirection_result['error']}")
    else:
        if redirection_result['vulnerability']:
            print("Potential Vulnerability Detected!")
        print(f"Reason: {redirection_result['reason']}")
    
    # Checking for HTTP security headers
    print('\nChecking for HTTP security headers...')
    headers_result = check_security_headers(url)
    if 'error' in headers_result:
        print(f"Error: {headers_result['error']}")
    else:
        if headers_result['vulnerability']:
            print("Potential Vulnerability Detected!")
        print(f"Reason: {headers_result['reason']}")

# Example usage
url = 'http://example.com'
scan_url(url)
