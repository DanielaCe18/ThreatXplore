document.getElementById('scan-form').addEventListener('submit', async function(event) {
    event.preventDefault();
    const url = document.getElementById('url-input').value;
    const scanType = document.querySelector('input[name="scan-type"]:checked').value;
    const resultDiv = document.getElementById('result');
    const targetUrlSpan = document.getElementById('target-url');
    const progressBar = document.getElementById('progress-bar');
    const progressContainer = document.getElementById('progress-container');
    const progressText = document.getElementById('progress-text');
  
    targetUrlSpan.textContent = url;
    resultDiv.innerHTML = '';
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
  
      results.forEach(result => {
        const resultDivContent = document.createElement('div');
        resultDivContent.classList.add('scan-result');
  
        if (result.type === 'whois') {
          resultDivContent.innerHTML = `
            <h3>WHOIS Scan Result</h3>
            <pre>${result.result}</pre>`;
        } else if (result.error) {
          resultDivContent.innerHTML = `
            <h3>${result.type.toUpperCase()} Scan Error</h3>
            <pre class="error">${result.error}</pre>`;
        } else {
          const vulnerabilityFound = result.result.toLowerCase().includes('vulnerability detected');
          const labelClass = vulnerabilityFound ? 'label-red' : 'label-green';
          const labelText = vulnerabilityFound ? 'Vulnerability Found' : 'No Vulnerability';
  
          resultDivContent.innerHTML = `
            <h3>${result.type.toUpperCase()} Scan Result <span class="label ${labelClass}">${labelText}</span></h3>
            <p>${vulnerabilityFound ? 'Vulnerability detected in the scan.' : 'No vulnerability detected in the scan.'}</p>`;
  
          if (vulnerabilityFound) {
            resultDivContent.innerHTML += `
              <button class="blue-team-btn" onclick="showBlueTeamInfo('${result.type}')">Blue Team</button>
              <button class="red-team-btn" onclick="showRedTeamInfo('${result.result}')">Red Team</button>`;
          }
        }
  
        resultDiv.appendChild(resultDivContent);
      });
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
      case 'whois':
        message = 'Ensure your domain registration details are up-to-date and accurate to prevent domain hijacking.';
        break;
      case 'sqli':
        message = 'Use parameterized queries and ORM libraries to prevent SQL Injection attacks.';
        break;
      case 'xss':
        message = 'Implement input validation, output encoding, and use Content Security Policy (CSP) to mitigate XSS risks.';
        break;
    }
    alert(message);
  }
  
  function showRedTeamInfo(result) {
    const payload = result.match(/with payload: (.+)/)[1];
    alert(`Payload used for the attack:\n\n${payload}`);
  }
  