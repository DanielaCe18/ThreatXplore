function scanURL() {
    const url = document.getElementById('urlInput').value;
    if (!url) {
        alert('Please enter a URL.');
        return;
    }

    document.getElementById('results').innerHTML = 'Scanning... Please wait.';
    
    // Mock scanning process
    setTimeout(() => {
        document.getElementById('results').innerHTML = `<strong>Scan Complete:</strong> No threats found for ${url}`;
    }, 3000);
}
