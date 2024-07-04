document.getElementById('scan-form').addEventListener('submit', async function(event) {
  event.preventDefault();
  const url = document.getElementById('url-input').value;
  const scanType = document.querySelector('input[name="scan-type"]:checked').value;
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
      body: JSON.stringify({ url, scan_type: scanType }),
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
          if (type === 'certificate_issues' || type === 'tls_ssl') {
            vulnerabilityFound = result.result && result.result.length > 0;
            details = Array.isArray(result.result) ? result.result.join('\n') : result.result;
          } else {
            vulnerabilityFound = result.vulnerable;
            details = Array.isArray(result.details) ? result.details.join('\n') : result.details;
          }

          const labelClass = vulnerabilityFound ? 'label-red' : 'label-green';
          const labelText = vulnerabilityFound ? 'Vulnerability Found' : 'No Vulnerability';

          resultDivContent.innerHTML = `
            <h3>${type.toUpperCase()} Scan Result <span class="label ${labelClass}">${labelText}</span></h3>
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
    case 'path_trasversal':
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
    case 'path_trasversal':
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
