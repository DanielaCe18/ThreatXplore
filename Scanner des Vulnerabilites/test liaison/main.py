from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from whois_utils import fetch_whois_info, format_whois_info
from sqli_xss_detect import scan_sql, scan_xss
from OS_command_injection import scan_os_command_injection
from ssti_detect import check_and_exploit_ssti
from cors_detect import check_and_exploit_cors  
from email_card_detect import find_emails, find_credit_cards
from xxe_detect import check_xxe_vulnerability
from ssrf_detect import check_ssrf
from csrf_detector import detect_csrf_vulnerability
from httpvuln_detect import check_uncommon_http_methods, check_redirections, check_security_headers
from robot_detect import check_robots_txt, detect_vulnerability_in_robots_txt
from lfi_detect import advanced_lfi_detection, check_lfi_vulnerability
from file_upload import check_and_exploit_file_upload
from path_trasversal import scan_path
from weak_auth_detect import check_common_passwords, brute_force_attack, check_account_lockout, load_passwords
from WebSocket import test_websocket, transform_url_to_ws
import asyncio
from crawler import start_crawling
import json

app = Flask(__name__, static_folder='')
CORS(app)  # Enable CORS for all routes

@app.route('/')
def serve_index():
    return send_from_directory('.', 'scan.html')

@app.route('/scan', methods=['POST'])
def scan():
    data = request.get_json()
    url = data.get('url')
    scan_type = data.get('scan_type')

    if not url:
        return jsonify({'message': 'URL is required'}), 400

    results = {}
    try:
        if scan_type in ['whois', 'all']:
            whois_info = fetch_whois_info(url)
            formatted_info = format_whois_info(whois_info)
            results['whois'] = {
                'result': formatted_info}
        if scan_type in ['crawl', 'all']:
            crawl_info = start_crawling(url)
            results['crawl'] = {
                'result': json.loads(crawl_info)}
    except Exception as e:
        results['crawl'] = {'error': str(e)}


    try:
        if scan_type in ['sqli', 'all']:
            sqli_results = scan_sql(url)
            sqli_vulnerable = any('vulnerability detected' in result.lower() for result in sqli_results)
            results['sqli'] = {
                'vulnerable': sqli_vulnerable,
                'details': sqli_results if sqli_vulnerable else 'No vulnerabilities detected'
            }
    except Exception as e:
        results['sqli'] = {'error': str(e)}

    try:
        if scan_type in ['xss', 'all']:
            xss_results = scan_xss(url)
            xss_vulnerable = any('vulnerability detected' in result.lower() for result in xss_results)
            results['xss'] = {
                'vulnerable': xss_vulnerable,
                'details': xss_results if xss_vulnerable else 'No vulnerabilities detected'
            }
    except Exception as e:
        results['xss'] = {'error': str(e)}

    try:
        if scan_type in ['os_command_injection', 'all']:
            os_command_results = scan_os_command_injection(url)
            os_command_vulnerable = 'visible injection detected' in os_command_results.lower()
            results['os_command_injection'] = {
                'vulnerable': os_command_vulnerable,
                'details': [os_command_results] if os_command_vulnerable else ['No vulnerabilities detected']
            }
    except Exception as e:
        results['os_command_injection'] = {'error': str(e)}

    try:
        if scan_type in ['ssti', 'all']:
            ssti_results = check_and_exploit_ssti(url)
            ssti_vulnerable = any('vulnerability detected' in result.lower() for result in ssti_results)
            results['ssti'] = {
                'vulnerable': ssti_vulnerable,
                'details': ssti_results if ssti_vulnerable else 'No vulnerabilities detected'
            }
    except Exception as e:
        results['ssti'] = {'error': str(e)}

    try:
        if scan_type in ['cors', 'all']:
            cors_results = check_and_exploit_cors(url)
            cors_vulnerable = any('Vulnerable' in result for result in cors_results)
            results['cors'] = {
                'vulnerable': cors_vulnerable,
                'details': cors_results if cors_vulnerable else 'No vulnerabilities detected'
            }
    except Exception as e:
        results['cors'] = {'error': str(e)}

    try:
        if scan_type in ['credit card', 'all']:
            card_results = find_credit_cards(url)
            card_vulnerable = len(card_results) > 0
            results['credit card'] = {
                'vulnerable': card_vulnerable,
                'details': card_results if card_vulnerable else 'No vulnerabilities detected'
            }
    except Exception as e:
        results['credit card'] = {'error': str(e)}

    try:
        if scan_type in ['email', 'all']:
            email_results = find_emails(url)
            email_vulnerable = len(email_results) > 0
            results['email'] = {
                'vulnerable': email_vulnerable,
                'details': email_results if email_vulnerable else 'No vulnerabilities detected'
            }
    except Exception as e:
        results['email'] = {'error': str(e)}

    try:
        if scan_type in ['xxe', 'all']:
            xxe_results = check_xxe_vulnerability(url)
            xxe_vulnerable = len(xxe_results) > 0
            results['xxe'] = {
                'vulnerable': xxe_vulnerable,
                'details': xxe_results if xxe_vulnerable else 'No vulnerabilities detected'
            }
    except Exception as e:
        results['xxe'] = {'error': str(e)}

    try:
        if scan_type in ['ssrf', 'all']:
            ssrf_results = check_ssrf(url)
            ssrf_vulnerable = any('SSRF' in result for result in ssrf_results)
            results['ssrf'] = {
                'vulnerable': ssrf_vulnerable,
                'details': ssrf_results if ssrf_vulnerable else 'No vulnerabilities detected'
            }
    except Exception as e:
        results['ssrf'] = {'error': str(e)}
    
    try:
        if scan_type in ['csrf', 'all']:
            csrf_results = detect_csrf_vulnerability(url)
            csrf_vulnerable = any('CSRF' in result for result in csrf_results)
            results['csrf'] = {
                'vulnerable': csrf_vulnerable,
                'details': csrf_results if csrf_vulnerable else 'No vulnerabilities detected'
            }
    except Exception as e:
        results['csrf'] = {'error': str(e)}

    try:
        if scan_type in ['http_methods', 'all']:
            methods_results = check_uncommon_http_methods(url)
            methods_vulnerable = any(result['vulnerability'] for result in methods_results)
            results['http_methods'] = {
                'vulnerable': methods_vulnerable,
                'details': [str(result) for result in methods_results] if methods_vulnerable else 'No vulnerabilities detected'
            }
    except Exception as e:
        results['http_methods'] = {'error': str(e)}

    try:
        if scan_type in ['redirections', 'all']:
            redirection_results = check_redirections(url)
            redirection_vulnerable = any(result['vulnerability'] for result in redirection_results)
            results['redirections'] = {
                'vulnerable': redirection_vulnerable,
                'details': [str(result) for result in redirection_results] if redirection_vulnerable else 'No vulnerabilities detected'
            }
    except Exception as e:
        results['redirections'] = {'error': str(e)}

    try:
        if scan_type in ['security_headers', 'all']:
            headers_results = check_security_headers(url)
            headers_vulnerable = any(result['vulnerability'] for result in headers_results)
            results['security_headers'] = {
                'vulnerable': headers_vulnerable,
                'details': [str(result) for result in headers_results] if headers_vulnerable else 'No vulnerabilities detected'
            }
    except Exception as e:
        results['security_headers'] = {'error': str(e)}
    
    try:
        if scan_type in ['robot', 'all']:
            robot_results = check_robots_txt(url)
            vulnerabilities = detect_vulnerability_in_robots_txt(robot_results)
            robot_vulnerable = len(vulnerabilities) > 0
            results['robot'] = {
                'vulnerable': robot_vulnerable,
                'details': vulnerabilities if robot_vulnerable else 'No vulnerabilities detected'
             }
    except Exception as e:
        results['robot'] = {'error': str(e)}
    
    try:
        if scan_type in ['lfi', 'all']:
            lfi_results = advanced_lfi_detection(url)
            lfi_vulnerable = any(result['vulnerable'] for result in lfi_results)
            details = [f"{result['name']}:\n{result['details']}" for result in lfi_results]
            results['lfi'] = {
                'vulnerable': lfi_vulnerable,
                'details': details if lfi_vulnerable else 'No vulnerabilities detected'
            }
    except Exception as e:
        results['lfi'] = {'error': str(e)}

    try:
        if scan_type in ['file_upload', 'all']:
            file_results = check_and_exploit_file_upload(url)
            file_vulnerable = any('available' in result for result in file_results)
            results['file_upload'] = {
                'vulnerable': file_vulnerable,
                'details': file_results if file_vulnerable else 'No vulnerabilities detected'
            }
    except Exception as e:
        results['file_upload'] = {'error': str(e)}
    
    try:
        if scan_type in ['path_trasversal', 'all']:
            path_results = scan_path(url)
            path_vulnerable = any('vulnerability' in result for result in path_results)
            results['path_trasversal'] = {
                'vulnerable': path_vulnerable,
                'details': path_results if path_vulnerable else 'No vulnerabilities detected'
            }
    except Exception as e:
        results['path_trasversal'] = {'error': str(e)}

    try:
        username = 'bee'
        password_file = 'common-password.txt'

        with open(password_file, 'r') as f:
            passwords = f.read().splitlines()
        
        if scan_type in ['common_passwords', 'all']:
            passwords_results = check_common_passwords(url, username, passwords)
            password_vulnerable = any('password found' in result for result in passwords_results)
            results['common_passwords'] = {
                'vulnerable': password_vulnerable,
                'details': passwords_results if password_vulnerable else 'No vulnerabilities detected'
            }
    except Exception as e:
        results['common_passwords'] = {'error': str(e)}

    try:
        username = 'bee'
        password_file = 'common-password.txt'

        with open(password_file, 'r') as f:
            passwords = f.read().splitlines()

        if scan_type in ['brut_force', 'all']:
            brut_results = brute_force_attack(url, username, passwords)
            brut_vulnerable = any('found' in result for result in brut_results)
            results['brut_force'] = {
                'vulnerable': brut_vulnerable,
                'details': brut_results if brut_vulnerable else 'No vulnerabilities detected'
            }
    except Exception as e:
        results['brut_force'] = {'error': str(e)}

    try:
        username = 'bee'
        if scan_type in ['account_lockout', 'all']:
            lockout_results = check_account_lockout(url, username)
            password_vulnerable = any('No account' in result for result in lockout_results)
            results['account_lockout'] = {
                'vulnerable': password_vulnerable,
                'details': lockout_results if password_vulnerable else 'No vulnerabilities detected'
            }
    except Exception as e:
        results['account_lockout'] = {'error': str(e)}

    try:
        if scan_type in ['websocket', 'all']:
            websocket_results = asyncio.run(test_websocket(transform_url_to_ws(url))) or []
            websocket_vulnerable = any('detected' in result for result in websocket_results)
            results['websocket'] = {
                'vulnerable': websocket_vulnerable,
                'details': websocket_results if websocket_vulnerable else 'No vulnerabilities detected'
            }
    except Exception as e:
        results['websocket'] = {'error': str(e)}

    return jsonify(results)

if __name__ == '__main__':
    app.run(debug=True)