import requests

def check_uncommon_http_methods(url):
    uncommon_methods = ['OPTIONS', 'TRACE', 'CONNECT', 'PUT', 'DELETE']
    vulnerabilities_found = False
    results = []

    for method in uncommon_methods:
        try:
            response = requests.request(method, url)
            status_code = response.status_code
            headers = response.headers
            body = response.text[:500]  # Limit body to first 500 chars for brevity
            
            if status_code not in [405, 501]:
                vulnerabilities_found = True
                results.append(f'{method} method is allowed with status code {status_code}.')
            else:
                results.append(f'{method} method is not allowed (status code {status_code}).')
        except Exception as e:
            vulnerabilities_found = True
            results.append(f'Error testing {method} method: {e}')

    return vulnerabilities_found, results


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
        'X-XSS-Protection',
        'Expect-CT',
        'Referrer-Policy'
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
    for result in methods_results:
        print(result)
    
    # Checking for HTTP redirections
    print('\nChecking for HTTP redirections...')
    redirection_result = check_redirections(url)
    print(redirection_result)
    
    # Checking for HTTP security headers
    print('\nChecking for HTTP security headers...')
    headers_result = check_security_headers(url)
    print(headers_result)

def main():
    # Example usage
    url = 'http://example.com'
    scan_url(url)

if __name__ == "__main__":
    main()
