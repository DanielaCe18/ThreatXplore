# :shield: ThreatXplore - Web Vulnerability Scanner :snake:

ThreatXplore is a web vulnerability scanner written in Python.

## How it works 

ThreatXplore operates as a comprehensive vulnerability scanner designed to scrutinize the pages of deployed web applications. It systematically extracts links and forms, conducts script attacks, sends payloads, and monitors for error messages, specific strings, or unusual behaviors. Upon identifying a vulnerability, ThreatXplore offers two options: a blue team button for preventative measures and a red team button for attack assistance. ThreatXplore is accessible via a website and as an executable file.

*<span style="color:red;">FYI: This is an annual school project.</span>* :loudspeaker:

![image](https://github.com/DanielaCe18/ThreatXplore/assets/145435353/c0149517-155e-4426-9b74-6807f7e7db4e)


## General features 
- One-step installation.
- Executes a multitude of security scanning tools, does other custom coded checks and prints the results spontaneously.
- Saves a lot of time.
- Vulnerability definitions guide you on what the vulnerability actually is and the threat it can pose.
- Remediation tells you how to plug/fix the found vulnerability.
- Provides you payloads and red team tips to attack.
- Supports HTTP and HTTPS.
- Generates vulnerability reports in TXT format.
- You can choose which vulnerabilities to detect and detect multiple ones at the same time.

## Vulnerability Checks
- :heavy_check_mark: SQL injections
- :heavy_check_mark: XSS
- :heavy_check_mark: OS command injection vulnerability
- :heavy_check_mark: Certificate Issues 
- :heavy_check_mark: SSL related Vulnerabilities 
- :heavy_check_mark: CORS vulnerabilities
- :heavy_check_mark: Unrestricted File Upload
- :heavy_check_mark: Local File Inclusion (LFI)
- :heavy_check_mark: Path traversal
- :heavy_check_mark: Email and Credit Card Disclosure
- :heavy_check_mark: Weak Authentication (common passwords, brute force, account lockout)
- :heavy_check_mark: Server-Side Request Forgery (SSRF)
- :heavy_check_mark: Server Side Template Injection vulnerabilities (SSTI)
- :heavy_check_mark: Cross-Site Request Forgery (CSRF)
- :heavy_check_mark: XML external entity injection (XXE)
- :heavy_check_mark: HTTP related vulnerabilities (redirections, security headers, uncommon methods)
- :heavy_check_mark: Robots.txt availability
- :heavy_check_mark: WebSocket Manipulation
- :heavy_check_mark: Crawler
- :heavy_check_mark: WHOIS information
- :heavy_check_mark: General Scan of IPs and domains

## Requirements
You need to have these installed on your machine:
- Unix systems preferred
- Python 3
- Nmap
- Docker

## Installation 

Clone this repository:

```sh
git clone https://github.com/DanielaCe18/ThreatXplore.git
```

## Usage 

### Without Docker:

Install requirements:
```sh
pip install -r requirements.txt
```

For the website:
1. Navigate to the `src/website_version` folder.
2. Run `python3 main.py`.
3. Navigate to `http://127.0.0.1:5000` once the Flask server is running.

For the application:
1. Navigate to the `src/application_version` folder.
2. Run `python3 app.py` and start scanning.

### With Docker:

For the website:
1. Locate to `Docker/`.
2. Build the Docker image: `docker build -t website .`
3. Run the Docker container: `docker run -p 5000:5000 website`

For the application:
1. Locate to `Docker/`.
2. Build the Docker image: `docker build -t app .`
3. Run the Docker container: `docker run -it --rm app`

## Licensing

ThreatXplore is released under the MIT licence by DanielaCe18. Source code is available on [GitHub](https://github.com/DanielaCe18/ThreatXplore).

## Disclaimer :warning:

Usage of ThreatXplore for attacking a target without prior consent of its owner is illegal. It is the end user's responsibility to obey all applicable local laws.
