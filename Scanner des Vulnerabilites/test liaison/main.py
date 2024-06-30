from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from whois_utils import fetch_whois_info, format_whois_info
from sqli_xss_detect import scan_sql, scan_xss

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

    results = []
    try:
        if scan_type in ['whois', 'all']:
            whois_info = fetch_whois_info(url)
            formatted_info = format_whois_info(whois_info)
            results.append({'type': 'whois', 'result': formatted_info})
    except Exception as e:
        results.append({'type': 'whois', 'error': str(e)})

    try:
        if scan_type in ['sqli', 'all']:
            sqli_results = scan_sql(url)
            results.append({'type': 'sqli', 'result': '\n'.join(sqli_results)})
    except Exception as e:
        results.append({'type': 'sqli', 'error': str(e)})

    try:
        if scan_type in ['xss', 'all']:
            xss_results = scan_xss(url)
            results.append({'type': 'xss', 'result': '\n'.join(xss_results)})
    except Exception as e:
        results.append({'type': 'xss', 'error': str(e)})

    return jsonify(results)

if __name__ == '__main__':
    app.run(debug=True)