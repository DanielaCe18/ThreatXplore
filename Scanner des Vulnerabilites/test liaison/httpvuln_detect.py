import requests

def check_uncommon_http_methods(url):
    uncommon_methods = ['OPTIONS', 'TRACE', 'CONNECT', 'PUT', 'DELETE']
    results = []

    for method in uncommon_methods:
        try:
            response = requests.request(method, url)
            status_code = response.status_code
            headers = response.headers
            content_type = headers.get('Content-Type', '')

            if 'text/html' in content_type.lower():
                body = response.text[:500]  # Limit body to first 500 chars for brevity
            else:
                body = ''

            if status_code not in [405, 501]:
                results.append({
                    'method': method,
                    'status_code': status_code,
                    'headers': dict(headers),
                    'body': body,
                    'vulnerability': True,
                    'reason': f'{method} method is allowed with status code {status_code}.'
                })
            else:
                results.append({
                    'method': method,
                    'status_code': status_code,
                    'vulnerability': False,
                    'reason': 'Method Not Allowed or Not Implemented.'
                })
        except Exception as e:
            results.append({'method': method, 'error': str(e), 'vulnerability': True, 'reason': 'Exception occurred.'})

    return results

def check_redirections(url):
    try:
        response = requests.get(url, allow_redirects=False)
        if response.is_redirect:
            return [{
                'vulnerability': True,
                'status_code': response.status_code,
                'location': response.headers.get('Location', ''),
                'reason': f'Redirects to: {response.headers.get("Location", "")}'
            }]
        else:
            return [{'vulnerability': False, 'reason': 'No redirection detected.'}]
    except Exception as e:
        return [{'vulnerability': True, 'error': str(e), 'reason': 'Exception occurred.'}]

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
            return [{
                'vulnerability': True,
                'missing_headers': missing_headers,
                'reason': f'Missing security headers: {", ".join(missing_headers)}'
            }]
        else:
            return [{'vulnerability': False, 'reason': 'All required security headers are present.'}]
    except Exception as e:
        return [{'vulnerability': True, 'error': str(e), 'reason': 'Exception occurred.'}]