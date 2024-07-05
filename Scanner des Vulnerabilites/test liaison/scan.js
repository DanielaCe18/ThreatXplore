document.getElementById('scan-form').addEventListener('submit', async function(event) {
  event.preventDefault();
  const url = document.getElementById('url-input').value;
  const scanTypes = Array.from(document.querySelectorAll('input[name="scan-type"]:checked')).map(cb => cb.value);
  const resultDiv = document.getElementById('result');
  const findingsDiv = document.getElementById('findings-result');
  const findingsSection = document.getElementById('findings-section');
  const targetUrlSpan = document.getElementById('target-url');
  const progressBar = document.getElementById('progress-bar');
  const progressContainer = document.getElementById('progress-container');
  const progressText = document.getElementById('progress-text');

  targetUrlSpan.textContent = url;
  resultDiv.innerHTML = '';
  findingsDiv.innerHTML = '';
  findingsSection.classList.add('hidden');
  progressContainer.classList.remove('hidden');
  progressBar.style.width = '0%';
  progressBar.innerHTML = '0%';
  progressText.textContent = 'Scanning target...';

  const updateProgressBar = (percentage) => {
    progressBar.style.width = percentage + '%';
    progressBar.innerHTML = percentage + '%';
  };

  // Simulate progress
  let progress = 0;
  const interval = setInterval(() => {
    if (progress < 90) {
      progress += 10;
      updateProgressBar(progress);
    } else {
      clearInterval(interval);
    }
  }, 300);

  try {
    const response = await fetch('/scan', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ url, scan_types: scanTypes }), // Updated to send multiple scan types
    });
    const results = await response.json();
    clearInterval(interval);
    updateProgressBar(100);
    progressText.textContent = 'Scan completed.';

    for (const [type, result] of Object.entries(results)) {
      const resultDivContent = document.createElement('div');
      resultDivContent.classList.add('scan-result');

      if (result.error) {
        resultDivContent.innerHTML = `
          <h3>${type.toUpperCase()} Scan Error</h3>
          <pre class="error">${result.error}</pre>`;
      } else {
        if (type === 'whois' || type === 'scan_gen') {
          resultDivContent.innerHTML = `
            <h3>${type.toUpperCase()} Scan Result</h3>
            <pre>${result.result}</pre>`;
        } else if (type === 'crawl') {
          resultDivContent.innerHTML = `
            <h3>${type.toUpperCase()} Scan Result</h3>
            <pre>${Array.isArray(result.result) ? result.result.join('\n') : result.result}</pre>`;
        } else {
          let vulnerabilityFound;
          let details;
          let description;
          if (type === 'certificate_issues' || type === 'tls_ssl') {
            vulnerabilityFound = result.result && result.result.length > 0;
            details = Array.isArray(result.result) ? result.result.join('\n') : result.result;
          } else {
            vulnerabilityFound = result.vulnerable;
            details = Array.isArray(result.details) ? result.details.join('\n') : result.details;
          }

          const labelClass = vulnerabilityFound ? 'label-red' : 'label-green';
          const labelText = vulnerabilityFound ? 'Vulnerability Found' : 'No Vulnerability';

          switch(type) {
            case 'sqli':
              description = 'SQL Injection is a web security vulnerability that allows an attacker to interfere with the queries that an application makes to its database. This can result in unauthorized access to sensitive data, modification of database content, or even administrative operations on the database.';
              break;
            case 'xss':
              description = 'Cross-Site Scripting (XSS) is a security vulnerability that allows attackers to inject malicious scripts into web pages viewed by other users, potentially stealing sensitive information, hijacking user sessions, or defacing websites.';
              break;
            case 'os_command_injection':
              description = 'OS Command Injection allows attackers to execute arbitrary operating system commands.';
              break;
            case 'ssti':
              description = 'Server-Side Template Injection (SSTI) is a security vulnerability that occurs when user input is unsafely incorporated into a server-side template, enabling attackers to execute arbitrary code on the server.';
              break;
            case 'cors':
              description = 'A CORS (Cross-Origin Resource Sharing) vulnerability arises when a web application’s CORS policy is misconfigured, allowing unauthorized domains to access restricted resources, which can lead to data theft or unauthorized actions.';
              break;
            case 'email':
              description = 'Email address disclosure can lead to spam, phishing attacks, and email-based threats.';
              break;
            case 'credit_card':
              description = 'Credit card information disclosure can result in financial fraud and identity theft.';
              break;
            case 'xxe':
              description = 'XML External Entity (XXE) is a security vulnerability that occurs when an XML input containing a reference to an external entity is processed by a weakly configured XML parser, leading to potential data exposure, denial of service, or server-side request forgery.';
              break;
            case 'ssrf':
              description = 'Server-Side Request Forgery (SSRF) is a security vulnerability that occurs when an attacker is able to induce a server-side application to make unauthorized requests to arbitrary domains, potentially leading to data exposure, internal network scanning, or interaction with internal services.';
              break;
            case 'csrf':
              description = 'Cross-Site Request Forgery (CSRF) is a security vulnerability that forces an authenticated user to perform unwanted actions on a web application in which they are currently authenticated, potentially leading to unauthorized state changes or data manipulation.';
              break;
            case 'http_methods':
              description = 'Uncommon HTTP Methods vulnerability occurs when a web server or application improperly handles or does not restrict uncommon HTTP methods like PUT, DELETE, TRACE, or OPTIONS, potentially leading to unauthorized actions or information disclosure.';
              break;
            case 'redirections':
              description = 'HTTP Redirection Vulnerability occurs when an application improperly handles redirection requests, allowing attackers to redirect users to malicious sites, leading to phishing attacks or further exploitation.';
              break;
            case 'security_headers':
              description = 'The lack of HTTP security headers is a vulnerability where a web application fails to implement headers that enhance security, such as Content-Security-Policy, X-Content-Type-Options, X-Frame-Options, and Strict-Transport-Security, making the application more susceptible to attacks like XSS, clickjacking, and MIME type sniffing.';
              break;
            case 'robot':
              description = 'Robots.txt Availability Vulnerability occurs when sensitive or critical URLs are inadvertently exposed through the robots.txt file, which is intended to guide web crawlers but can be accessed by attackers to discover hidden parts of the application.';
              break;
            case 'lfi':
              description = 'Local File Inclusion (LFI) is a security vulnerability that occurs when an application allows users to include files from the local server through manipulated input, potentially leading to arbitrary file access, sensitive data exposure, or remote code execution.';
              break;
            case 'file_upload':
              description = 'Unrestricted File Upload is a security vulnerability that occurs when an application does not properly validate or restrict the types of files that users can upload, potentially allowing attackers to upload malicious files that can be executed on the server.';
              break;
            case 'path_traversal':
              description = 'Path Traversal is a security vulnerability that occurs when an application improperly validates user input, allowing attackers to access files and directories outside the intended directory, potentially leading to sensitive data exposure or execution of arbitrary code.';
              break;
            case 'common_passwords':
              description = 'Weak or predictable passwords that can be easily guessed or cracked.';
              break;
            case 'brut_force':
              description = 'Attackers attempt to gain access by systematically trying all possible combinations of passwords.';
              break;
            case 'account_lockout':
              description = 'Users can be locked out of their accounts after a number of failed login attempts, which can be exploited to cause denial of service.';
              break;
            case 'websocket':
              description = 'Manipulation Vulnerability occurs when an application improperly handles WebSocket communications, allowing attackers to intercept, modify, or inject messages, leading to unauthorized actions, data theft, or further exploitation.';
              break;
            case 'certificate_issues':
              description = 'Issues with certificates can lead to insecure communications and man-in-the-middle attacks.';
              break;
            case 'tls_ssl':
              description = 'Weaknesses in TLS/SSL configurations can expose data to interception and tampering.';
              break;
            case 'scan_ports':
              description = 'Open ports can expose services to the internet that might be vulnerable to attacks.';
              break;
            default:
              description = 'Description not available.';
              break;
          }

          resultDivContent.innerHTML = `
            <h3>${type.toUpperCase()} Scan Result <span class="label ${labelClass}">${labelText}</span></h3>
            <p>${description}</p>
            <p>${vulnerabilityFound ? 'Vulnerability detected in the scan.' : 'No vulnerability detected in the scan.'}</p>`;

          if (vulnerabilityFound) {
            // Properly escape the details for safe insertion into HTML
            const escapedDetails = escapeHtml(details);

            resultDivContent.innerHTML += `
              <button class="blue-team-btn" onclick="showBlueTeamInfo('${type}')">Blue Team</button>
              <button class="red-team-btn" onclick="showRedTeamInfo('${type}', \`${escapedDetails}\`)">Red Team</button>`;
          }
        }
      }

      resultDiv.appendChild(resultDivContent);
      findingsDiv.appendChild(resultDivContent);
    }

    findingsSection.classList.remove('hidden');
  } catch (error) {
    clearInterval(interval);
    updateProgressBar(100);
    progressText.textContent = 'Scan completed with errors.';
    resultDiv.innerHTML = `<p class="error">Error: ${error.message}</p>`;
  }
});

function showBlueTeamInfo(scanType) {
  let message = '';
  switch(scanType) {
    case 'sqli':
      message = 'Use parameterized queries or prepared statements to prevent malicious SQL code execution.';
      break;
    case 'xss':
      message = 'Implement input validation, output encoding, and use Content Security Policy (CSP) to mitigate XSS risks.';
      break;
    case 'os_command_injection':
      message = 'Use parameterized functions or APIs that execute commands without directly involving shell interpreters.';
      break;
    case 'ssti':
      message = 'Validate and sanitize all user inputs, and avoid using user input directly in templates.';
      break;
    case 'cors':
      message = 'Properly configure the CORS policy to specify allowed origins, methods, and headers, and avoid using wildcards.';
      break;
    case 'email':
      message = 'Use methods like encoding email addresses, using contact forms, displaying email addresses as images, implementing CAPTCHA on forms, using CSS techniques, leveraging email address cloaking tools, and employing JavaScript frameworks to protect email addresses from disclosure on websites.';
      break;
    case 'credit card':
      message = 'Use encryption (SSL/TLS) for data transmission, implement tokenization, follow PCI DSS compliance, use secure payment gateways, regularly update and patch systems, monitor for suspicious activity, and educate users on security practices to protect credit card information disclosure on websites.';
      break;
    case 'xxe':
      message = 'Disable external entity processing in XML parsers to prevent the inclusion of malicious external entities.';
      break;
    case 'ssrf':
      message = 'Implement strict input validation and sanitation, limit outbound connections, use a whitelist of permitted URLs, and employ network segmentation to restrict internal network access.';
      break;
    case 'csrf':
      message = 'Implement anti-CSRF tokens for each user session and validate them with each state-changing request.';
      break;
    case 'http_methods':
      message = 'Disable or properly configure uncommon HTTP methods in the web server or application settings.';
      break;
    case 'redirections':
      message = 'Validate and restrict URLs used in redirection, ensuring they are within a trusted domain.';
      break;
    case 'security_headers':
      message = 'Configure and implement appropriate HTTP security headers to protect against common web vulnerabilities.';
      break;
    case 'robot':
      message = 'Avoid listing sensitive or confidential URLs in the robots.txt file and use alternative methods for securing these URLs.';
      break;
    case 'lfi':
      message = 'Validate and sanitize user input to prevent directory traversal and file inclusion attacks';
      break;
    case 'file_upload':
      message = 'Implement strict file type validation, limit upload size, and use secure storage locations for uploaded files.';
      break;
    case 'path_traversal':
      message = 'Validate and sanitize user input to prevent directory traversal sequences like ../ from being processed.';
      break;
    case 'common_passwords':
      message = 'Implement strong password policies, use password managers, enforce regular password changes, and enable multi-factor authentication.';
      break;
    case 'brut_force':
      message = 'Limit login attempts, implement CAPTCHA, use account lockout mechanisms, and enforce strong password policies.';
      break;
    case 'account_lockout':
      message = 'Implement CAPTCHA, monitor for unusual activity, provide a secure way to unlock accounts, and limit lockout durations.';
      break;
    case 'websocket':
      message = 'Implement strong authentication, input validation, and use secure WebSocket protocols (wss://) to protect communications.';
      break;
    case 'certificate_issues':
      message = 'Implement strict certificate validation policies, including checking the certificate chain, expiration date, and revocation status.';
      break;
    case 'tls_ssl':
      message = 'Defense measures include updating OpenSSL, disabling outdated protocols (SSL 3.0, TLS 1.0), enforcing HSTS, supporting only secure ciphers, and ensuring servers are configured to use strong security practices.';
      break;
    case 'scan_ports':
      message = 'Close unnecessary ports and implement proper firewall rules and access controls';
      break
  }
  alert(message);
}

function showRedTeamInfo(scanType, result) {
  let message = '';
  switch(scanType) {
    case 'sqli':
      message = `${result}`;
      break;
    case 'xss':
      message = `${result}`;
      break;
    case 'os_command_injection':
      message = `${result}`;
      break;
    case 'ssti':
      message = `${result}`;
      break;
    case 'cors':
      message = `${result}`;
      break;
    case 'email':
      message = `${result}`;
      break;
    case 'credit card':
      message = `${result}`;
      break;
    case 'xxe':
      message = `${result}`;
      break;
    case 'ssrf':
      message = `SSRF vulnerability detected: ${result}`;
      break;
    case 'csrf':
      message = `${result}`;
      break;
    case 'http_methods':
      message = `Uncommon HTTP methods vulnerability detected: ${result}`;
      break;
    case 'redirections':
      message = `Redirection vulnerability detected: ${result}`;
      break;
    case 'security_headers':
      message = `Security headers missing: ${result}`;
      break;
    case 'robot':
      message = `Robots.txt vulnerability detected and here is it's content: ${result}`;
      break;
    case 'lfi':
      message = `LFI vulnerability detected: ${result}`;
      break;
    case 'file_upload':
      message = `${result}`;
      break;
    case 'path_traversal':
      message = `${result}`;
      break;
    case 'common_passwords':
      message = `${result}`;
      break;
    case 'brut_force':
      message = `Brut force executed : ${result}`;
      break;
    case 'account_lockout':
      message = `${result}`;
      break;
    case 'websocket':
      message = `${result}`;
      break;
    case 'certificate_issues':
      message = `${result}`;
      break;
    case 'tls_ssl':
      message = `${result}`;
      break;
    case 'scan_ports':
      message = `Open ports detected: ${result}`;
      break;
  }
  alert(message);
}

function escapeHtml(unsafe) {
  if (!unsafe) return '';
  return unsafe
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
