document.addEventListener('DOMContentLoaded', function () {
    renderVulnerabilitiesBySeverityChart();
    renderTopVulnerabilitiesChart();
    renderAttacksByVulnerabilityChart();
    renderWorldMap();
});

// Simulated data fetching function for Vulnerabilities by Severity
async function fetchVulnerabilitySeverityData() {
    return [
        { label: 'High', percentage: 35 },
        { label: 'Medium', percentage: 45 },
        { label: 'Low', percentage: 20 }
    ];
}

function renderVulnerabilitiesBySeverityChart() {
    fetchVulnerabilitySeverityData().then(data => {
        var ctx = document.getElementById('severityChart').getContext('2d');
        var chartData = {
            labels: data.map(item => item.label),
            datasets: [{
                label: 'Vulnerability Severity Percentage',
                data: data.map(item => item.percentage),
                backgroundColor: [
                    'rgba(255, 99, 132, 0.8)', // High severity - red
                    'rgba(255, 206, 86, 0.8)', // Medium severity - yellow
                    'rgba(75, 192, 192, 0.8)'  // Low severity - green
                ]
            }]
        };
        var chartOptions = {
            indexAxis: 'y',
            scales: {
                x: {
                    beginAtZero: true,
                    ticks: {
                        callback: function(value) {
                            return value + "%";
                        }
                    }
                }
            },
            responsive: true,
            maintainAspectRatio: false
        };
        new Chart(ctx, { type: 'bar', data: chartData, options: chartOptions });
    });
}

// Update for OWASP Top Ten 2023
function renderTopVulnerabilitiesChart() {
    var ctx = document.getElementById('topVulnerabilitiesChart').getContext('2d');
    var topVulnerabilitiesChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Injection', 'Broken Authentication', 'Sensitive Data Exposure', 'XML External Entities (XXE)', 'Broken Access Control', 'Security Misconfiguration', 'Cross-Site Scripting (XSS)', 'Insecure Deserialization', 'Using Components with Known Vulnerabilities', 'Insufficient Logging & Monitoring'],
            datasets: [{
                data: [15, 12, 11, 10, 9, 8, 7, 6, 5, 4],
                backgroundColor: ['#FF6384', '#36A2EB', '#FFCE56', '#E7E9ED', '#4BC0C0', '#FF9F40', '#BDB76B', '#C71585', '#4682B4', '#32CD32']
            }]
        }
    });
}

function renderWorldMap() {
    var map = L.map('attacksMap', { zoomControl: false }).setView([20, 0], 2);
    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
        attribution: 'Map data &copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors',
        maxZoom: 18
    }).addTo(map);

    // Example of highlighting - statically defined
    var countries = [{ lat: 51.5, lon: -0.09, popup: 'High activity in UK' }, { lat: 38.9072, lon: -77.0369, popup: 'High activity in USA' }];
    countries.forEach(country => {
        L.marker([country.lat, country.lon]).addTo(map)
            .bindPopup(country.popup)
            .openPopup();
    });
}

function renderAttacksByVulnerabilityChart() {
    var ctx = document.getElementById('attacksVulnerabilityChart').getContext('2d');
    var attacksByVulnerabilityChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: ['SQL Injection', 'XSS', 'CSRF', 'RCE', 'DoS'],
            datasets: [{
                label: 'Number of Attacks',
                data: [300, 250, 200, 160, 120], // Simulated data
                backgroundColor: [
                    'rgba(255, 99, 132, 0.2)',
                    'rgba(54, 162, 235, 0.2)',
                    'rgba(255, 206, 86, 0.2)',
                    'rgba(75, 192, 192, 0.2)',
                    'rgba(153, 102, 255, 0.2)'
                ],
                borderColor: [
                    'rgba(255, 99, 132, 1)',
                    'rgba(54, 162, 235, 1)',
                    'rgba(255, 206, 86, 1)',
                    'rgba(75, 192, 192, 1)',
                    'rgba(153, 102, 255, 1)'
                ],
                borderWidth: 1
            }]
        },
        options: {
            scales: {
                y: {
                    beginAtZero: true
                }
            },
            responsive: true
        }
    });
}
