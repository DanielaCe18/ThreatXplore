from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from whois_utils import fetch_whois_info, format_whois_info
from sqli_xss_detect import scan_sql, scan_xss
from OS_command_injection import scan_os_command_injection
from ssti_detect import check_and_exploit_ssti
from cors_detect import check_and_exploit_cors  # Import the CORS detection function
from email_card_detect import find_emails, find_credit_cards

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
            results['whois'] = {'result': formatted_info}
    except Exception as e:
        results['whois'] = {'error': str(e)}

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
                'details': os_command_results
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

    return jsonify(results)

if __name__ == '__main__':
    app.run(debug=True)
