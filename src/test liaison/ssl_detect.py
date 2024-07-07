import socket
import ssl
from OpenSSL import SSL
import datetime
import requests
import subprocess
import re

def get_certificate(url):
    """
    Retrieves the SSL certificate for a given URL.
    
    Args:
        url (str): The URL to retrieve the certificate from.
    
    Returns:
        dict: The SSL certificate details, or None if an error occurs.
    """
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

def check_certificate_issues(url):
    """
    Checks for issues in the SSL certificate of a given URL.
    
    Args:
        url (str): The URL to check for certificate issues.
    
    Returns:
        list: A list of detected certificate issues.
    """
    cert = get_certificate(url)
    if not cert:
        return ["Unable to retrieve certificate"]

    issues = []

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

    # Hostname Mismatch
    hostname = url.split("//")[-1].split("/")[0]
    common_name = [entry[0][1] for entry in cert['subject'] if entry[0][0] == 'commonName'][0]
    if hostname != common_name:
        issues.append(f"Hostname mismatch: certificate is for {common_name}")

    # Certificate Pinning
    if cert['issuer'] == cert['subject']:
        issues.append("Self-signed certificate")
    else:
        issues.append("Certificate pinning must be checked on the client side")

    # Certificate Chain
    output = subprocess.getoutput(f"openssl s_client -showcerts -connect {hostname}:443")
    if 'Verify return code: 0 (ok)' not in output:
        issues.append("Certificate chain issue")

    # OCSP Stapling
    output = subprocess.getoutput(f"openssl s_client -status -connect {hostname}:443")
    if 'OCSP Response Status: successful' not in output:
        issues.append("OCSP stapling not supported")

    # DNS CAA Records
    output = subprocess.getoutput(f"dig caa {hostname} +short")
    if not output:
        issues.append("No DNS CAA records found")

    return issues

def check_ssltls(url):
    """
    Checks for SSL/TLS vulnerabilities on a given URL.
    
    Args:
        url (str): The URL to check for SSL/TLS vulnerabilities.
    
    Returns:
        list: A list of detected SSL/TLS vulnerabilities.
    """
    issues = []
    hostname = url.split("//")[-1].split("/")[0]

    # SSL/TLS Protocols
    protocols = ['TLSv1', 'TLSv1_1', 'TLSv1_2', 'TLSv1_3']
    for proto in protocols:
        try:
            context = ssl.SSLContext(getattr(ssl, f"PROTOCOL_{proto.replace('.', '_').upper()}"))
            with socket.create_connection((hostname, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    pass
            issues.append(f"{proto} supported")
        except AttributeError:
            issues.append(f"Error checking {proto}: {proto} is not supported by the ssl module")
        except ssl.SSLError:
            pass
        except Exception as e:
            issues.append(f"Error checking {proto}: {e}")

    # Weak Ciphers
    output = subprocess.getoutput(f"sslscan {hostname}")
    weak_ciphers = re.findall(r'(RC4|DES|3DES)', output)
    issues.extend(weak_ciphers)

    # Perfect Forward Secrecy
    if 'DH' in output:
        issues.append("No Perfect Forward Secrecy (PFS)")

    # Implementation Flaws
    # Heartbleed
    result = subprocess.getoutput(f"nmap --script ssl-heartbleed -p 443 {hostname}")
    if "VULNERABLE" in result:
        issues.append("Vulnerable to Heartbleed")

    # POODLE
    result = subprocess.getoutput(f"nmap --script ssl-poodle -p 443 {hostname}")
    if "VULNERABLE" in result:
        issues.append("Vulnerable to POODLE")

    # BEAST
    output = subprocess.getoutput(f"testssl.sh --beast {hostname}")
    if 'not vulnerable' not in output:
        issues.append("Vulnerable to BEAST")

    # CRIME and BREACH
    output = subprocess.getoutput(f"testssl.sh --crime --breach {hostname}")
    if 'not vulnerable' not in output:
        issues.append("Vulnerable to CRIME/BREACH")

    # HSTS
    try:
        response = requests.get(f"https://{hostname}")
        if 'Strict-Transport-Security' not in response.headers:
            issues.append("HSTS not implemented")
    except Exception as e:
        issues.append(f"Error checking HSTS: {e}")

    # TLS Fallback SCSV
    output = subprocess.getoutput(f"testssl.sh --fallback {hostname}")
    if 'not vulnerable' not in output:
        issues.append("TLS Fallback SCSV not supported")

    # Insecure Renegotiation
    output = subprocess.getoutput(f"testssl.sh --reneg {hostname}")
    if 'Secure Renegotiation IS supported' not in output:
        issues.append("Insecure renegotiation")

    # TLS 1.3 Support
    if 'TLSv1.3' not in output:
        issues.append("TLS 1.3 not supported")

    return issues

if __name__ == "__main__":
    target_url = input('Enter the URL to test for vulnerability: ')
    certificate_results = check_certificate_issues(target_url)
    print("\nCertificate Issues:")
    if certificate_results:
        for result in certificate_results:
            print(f"- {result}")
    else:
        print("No certificate issues found.")
    
    ssl_tls_results = check_ssltls(target_url)
    print("\nSSL/TLS Issues:")
    if ssl_tls_results:
        for result in ssl_tls_results:
            print(f"- {result}")
    else:
        print("No SSL/TLS issues found.")
