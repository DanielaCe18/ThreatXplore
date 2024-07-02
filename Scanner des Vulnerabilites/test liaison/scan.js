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
        if (type === 'whois') {
          resultDivContent.innerHTML = `
            <h3>${type.toUpperCase()} Scan Result</h3>
            <pre>${result.result}</pre>`;
        } else {
          const vulnerabilityFound = result.vulnerable;
          const labelClass = vulnerabilityFound ? 'label-red' : 'label-green';
          const labelText = vulnerabilityFound ? 'Vulnerability Found' : 'No Vulnerability';

          resultDivContent.innerHTML = `
            <h3>${type.toUpperCase()} Scan Result <span class="label ${labelClass}">${labelText}</span></h3>
            <p>${vulnerabilityFound ? 'Vulnerability detected in the scan.' : 'No vulnerability detected in the scan.'}</p>`;

          if (vulnerabilityFound) {
            // Properly escape the details for safe insertion into HTML
            const escapedDetails = escapeHtml(result.details.join('\n'));

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
      message = 'Use parameterized queries and ORM libraries to prevent SQL Injection attacks.';
      break;
    case 'xss':
      message = 'Implement input validation, output encoding, and use Content Security Policy (CSP) to mitigate XSS risks.';
      break;
    case 'os_command_injection':
      message = 'Use proper input validation and sanitization to prevent OS Command Injection attacks.';
      break;
    case 'ssti':
      message = 'Ensure proper input validation and escaping to prevent SSTI vulnerabilities.';
      break;
    case 'cors':
      message = 'Ensure proper CORS configuration to prevent unauthorized access from untrusted origins.';
      break;
    case 'email':
      message = 'Use methods like encoding email addresses, using contact forms, displaying email addresses as images, implementing CAPTCHA on forms, using CSS techniques, leveraging email address cloaking tools, and employing JavaScript frameworks to protect email addresses from disclosure on websites.';
      break;
    case 'credit card':
      message = 'Use encryption (SSL/TLS) for data transmission, implement tokenization, follow PCI DSS compliance, use secure payment gateways, regularly update and patch systems, monitor for suspicious activity, and educate users on security practices to protect credit card information disclosure on websites.';
      break;
    case 'xxe':
      message = 'Ensure your XML parsers are securely configured to disable external entity processing.';
      break;
    case 'ssrf':
      message = 'Implement strict input validation and sanitation, limit outbound connections, use a whitelist of permitted URLs, and employ network segmentation to restrict internal network access.';
      break;
    case 'csrf':
      message = 'Implement anti-CSRF tokens for each user session and validate them with each state-changing request.';
      break;
    case 'http_methods':
      message = 'test';
      break;
    case 'redirections':
      message = 'test';
      break
    case 'security_headers':
      message = 'test';
      break
    case 'robot':
      message = 'test';
      break
  }
  alert(message);
}

function showRedTeamInfo(scanType, result) {
  let message = '';
  switch(scanType) {
    case 'sqli':
      message = `SQLi vulnerability detected: ${result}`;
      break;
    case 'xss':
      message = `XSS vulnerability detected: ${result}`;
      break;
    case 'os_command_injection':
      message = `OS Command Injection vulnerability detected: ${result}`;
      break;
    case 'ssti':
      message = `SSTI vulnerability detected: ${result}`;
      break;
    case 'cors':
      message = `CORS vulnerability detected: ${result}`;
      break;
    case 'email':
      message = `Email disclosure detected: ${result}`;
      break;
    case 'credit card':
      message = `Credit card disclosure detected: ${result}`;
      break;
    case 'xxe':
      message = `XXE vulnerability detected: ${result}`;
      break;
    case 'ssrf':
      message = `SSRF vulnerability detected: ${result}`;
      break;
    case 'csrf':
      message = `CSRF vulnerability detected: ${result}`;
      break;
    case 'http_methods':
      message = `Uncommon HTTP methods vulnerability detected: ${result}`;
      break;
    case 'redirections':
      message = `Redirection vulnerability detected: ${result}`;
      break;
    case 'security_headers':
      message = `Uncommon security headers vulnerability detected: ${result}`;
      break;
    case 'robot':
      message = `Robots.txt vulnerability detected: ${result}`;
      break;
  }
  alert(message);
}

function escapeHtml(unsafe) {
  return unsafe
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
