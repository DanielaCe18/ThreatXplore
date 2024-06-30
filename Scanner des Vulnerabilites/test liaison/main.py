from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from whois_utils import fetch_whois_info, format_whois_info
from sqli_xss_detect import scan_sql, scan_xss
from OS_command_injection import scan_os_command_injection  # Import the OS Command Injection scan function

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

    return jsonify(results)

if __name__ == '__main__':
    app.run(debug=True)
