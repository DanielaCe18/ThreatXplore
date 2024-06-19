import socket
import ssl
from OpenSSL import SSL
import datetime
import requests
import subprocess
import re

def get_certificate(url):
    try:
        hostname = url.split("//")[-1].split("/")[0]
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                return cert
    except Exception as e:
        print(f"Error getting certificate: {e}")
        return None

def check_certificate_issues(cert):
    issues = []
    if not cert:
        return ["Unable to retrieve certificate"]
    
    # Expired Certificates
    not_after = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
    if not_after < datetime.datetime.now():
        issues.append("Expired certificate")

    # Self-Signed Certificates
    if 'issuer' in cert and cert['issuer'] == cert['subject']:
        issues.append("Self-signed certificate")

    # Weak Signature Algorithms
    sig_alg = cert.get('signatureAlgorithm')
    if sig_alg and ('md5' in sig_alg or 'sha1' in sig_alg):
        issues.append("Weak signature algorithm")

    return issues

def check_mismatched_hostnames(cert, url):
    hostname = url.split("//")[-1].split("/")[0]
    common_name = [entry[0][1] for entry in cert['subject'] if entry[0][0] == 'commonName'][0]
    if hostname != common_name:
        return ["Hostname mismatch: certificate is for " + common_name]
    return []

def check_ssl_tls_protocols(url):
    protocols = ['ssl2', 'ssl3', 'tls1', 'tls1_1']
    issues = []
    for proto in protocols:
        try:
            context = ssl.SSLContext(getattr(ssl, f"PROTOCOL_{proto.upper()}"))
            with socket.create_connection((url, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=url) as ssock:
                    pass
            issues.append(f"{proto.upper()} supported")
        except ssl.SSLError:
            pass
        except Exception as e:
            issues.append(f"Error checking {proto.upper()}: {e}")
    return issues

def check_weak_ciphers(url):
    output = subprocess.getoutput(f"sslscan {url}")
    weak_ciphers = re.findall(r'(RC4|DES|3DES)', output)
    return weak_ciphers

def check_perfect_forward_secrecy(url):
    output = subprocess.getoutput(f"sslscan {url}")
    if 'DH' in output:
        return ["No Perfect Forward Secrecy (PFS)"]
    return []

def check_implementation_flaws(url):
    flaws = []
    # Heartbleed
    result = subprocess.getoutput(f"nmap --script ssl-heartbleed -p 443 {url}")
    if "VULNERABLE" in result:
        flaws.append("Heartbleed")

    # POODLE
    result = subprocess.getoutput(f"nmap --script ssl-poodle -p 443 {url}")
    if "VULNERABLE" in result:
        flaws.append("POODLE")

    # BEAST
    output = subprocess.getoutput(f"testssl.sh --beast {url}")
    if 'not vulnerable' not in output:
        flaws.append("BEAST")

    # CRIME and BREACH
    output = subprocess.getoutput(f"testssl.sh --crime --breach {url}")
    if 'not vulnerable' not in output:
        flaws.append("CRIME/BREACH")

    return flaws

def check_hsts(url):
    try:
        response = requests.get(f"https://{url}")
        if 'Strict-Transport-Security' not in response.headers:
            return ["HSTS not implemented"]
    except Exception as e:
        return [f"Error checking HSTS: {e}"]
    return []

def check_certificate_pinning(url):
    cert = get_certificate(url)
    if not cert:
        return ["Unable to retrieve certificate"]
    if cert['issuer'] == cert['subject']:
        return ["Self-signed certificate"]
    return ["Certificate pinning must be checked on the client side"]

def check_tls_fallback_scsv(url):
    output = subprocess.getoutput(f"testssl.sh --fallback {url}")
    if 'not vulnerable' not in output:
        return ["TLS Fallback SCSV not supported"]
    return []

def check_insecure_renegotiation(url):
    output = subprocess.getoutput(f"testssl.sh --reneg {url}")
    if 'Secure Renegotiation IS supported' not in output:
        return ["Insecure renegotiation"]
    return []

def check_tls_1_3_support(url):
    output = subprocess.getoutput(f"sslscan {url}")
    if 'TLSv1.3' not in output:
        return ["TLS 1.3 not supported"]
    return []

def check_certificate_chain(url):
    output = subprocess.getoutput(f"openssl s_client -showcerts -connect {url}:443")
    if 'Verify return code: 0 (ok)' not in output:
        return ["Certificate chain issue"]
    return []

def check_ocsp_stapling(url):
    output = subprocess.getoutput(f"openssl s_client -status -connect {url}:443")
    if 'OCSP Response Status: successful' not in output:
        return ["OCSP stapling not supported"]
    return []

def check_dns_caa_records(url):
    hostname = url.split("//")[-1].split("/")[0]
    output = subprocess.getoutput(f"dig caa {hostname} +short")
    if not output:
        return ["No DNS CAA records found"]
    return []

def check_headers(url):
    headers_issues = []
    try:
        response = requests.get(f"https://{url}")
        headers = response.headers
        
        # Check HSTS
        if 'Strict-Transport-Security' not in headers:
            headers_issues.append("HSTS not implemented")

        # Check Expect-CT
        if 'Expect-CT' not in headers:
            headers_issues.append("Expect-CT header not set")

        # Check Content Security Policy (CSP)
        if 'Content-Security-Policy' not in headers:
            headers_issues.append("Content Security Policy (CSP) not implemented")

        # Check Referrer Policy
        if 'Referrer-Policy' not in headers:
            headers_issues.append("Referrer Policy header not set")

        # Check X-Content-Type-Options
        if 'X-Content-Type-Options' not in headers or headers['X-Content-Type-Options'] != 'nosniff':
            headers_issues.append("X-Content-Type-Options header not set to 'nosniff'")

        # Check X-Frame-Options
        if 'X-Frame-Options' not in headers:
            headers_issues.append("X-Frame-Options header not set")

        # Check X-XSS-Protection
        if 'X-XSS-Protection' not in headers or headers['X-XSS-Protection'] != '1; mode=block':
            headers_issues.append("X-XSS-Protection header not set to '1; mode=block'")
    except Exception as e:
        headers_issues.append(f"Error checking headers: {e}")
    return headers_issues

def scan_url(url):
    results = {}
    cert = get_certificate(url)

    # Certificate issues
    results['certificate_issues'] = check_certificate_issues(cert)
    results['mismatched_hostnames'] = check_mismatched_hostnames(cert, url)

    # Protocol issues
    results['protocol_issues'] = check_ssl_tls_protocols(url)

    # Configuration issues
    results['weak_ciphers'] = check_weak_ciphers(url)
    results['pfs_issues'] = check_perfect_forward_secrecy(url)

    # Implementation flaws
    results['implementation_flaws'] = check_implementation_flaws(url)

    # Misconfigurations
    results['hsts_issues'] = check_hsts(url)
    results['certificate_pinning'] = check_certificate_pinning(url)
    results['tls_fallback_scsv'] = check_tls_fallback_scsv(url)
    results['insecure_renegotiation'] = check_insecure_renegotiation(url)

    # Enhanced checks
    results['tls_1_3_support'] = check_tls_1_3_support(url)
    results['certificate_chain'] = check_certificate_chain(url)
    results['ocsp_stapling'] = check_ocsp_stapling(url)
    results['dns_caa_records'] = check_dns_caa_records(url)
    results['header_issues'] = check_headers(url)

    return results

if __name__ == "__main__":
    url = input("Enter the URL to scan: ")
    url = url.replace('https://', '').replace('http://', '').strip('/')
    scan_results = scan_url(url)

    for key, value in scan_results.items():
        print(f"{key}: {value}")
