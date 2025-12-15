// Main front-end logic for the DetMeter plugin
let detectionChart = null;

async function analyzeOperation() {
    const opId = document.getElementById('operationId').value.trim();
    if (!opId) {
        alert('Please enter an Operation ID.');
        return;
    }

    try {
        const response = await fetch('/plugin/detmeter/api/analyze', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ operation_id: opId })
        });
        const data = await response.json();

        if (data.error) {
            alert('Error: ' + data.error);
            return;
        }

        // Display operation info
        document.getElementById('opName').textContent = `${data.operation_name} (${data.operation_id})`;
        
        // Prepare data for the chart
        const siemNames = Object.keys(data.siem_results);
        const detectionRates = siemNames.map(name => data.siem_results[name].detection_rate.toFixed(1));
        const colors = ['#3498db', '#2ecc71', '#e74c3c', '#f39c12', '#9b59b6'];

        // Create or update the bar chart
        const ctx = document.getElementById('detectionChart').getContext('2d');
        if (detectionChart) detectionChart.destroy();
        
        detectionChart = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: siemNames,
                datasets: [{
                    label: 'Detection Rate (%)',
                    data: detectionRates,
                    backgroundColor: colors,
                    borderColor: colors.map(c => c.replace('0.8', '1')),
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true,
                        max: 100,
                        title: { display: true, text: 'Detection Rate %' }
                    },
                    x: { title: { display: true, text: 'SIEM System' } }
                },
                plugins: {
                    legend: { display: false },
                    tooltip: { callbacks: { label: ctx => `Detection: ${ctx.raw}%` } }
                }
            }
        });

        // Build a results table
        let tableHtml = `<h4>Detailed Results</h4><table style="width:100%; border-collapse:collapse; margin-top:20px;">`;
        tableHtml += `<tr><th>SIEM</th><th>Detection Rate</th><th>Techniques Detected</th><th>Total Events</th></tr>`;
        for (const [siem, results] of Object.entries(data.siem_results)) {
            tableHtml += `<tr>
                <td><strong>${siem}</strong></td>
                <td>${results.detection_rate.toFixed(1)}%</td>
                <td>${results.techniques_detected.length} / ${data.techniques_used.length}</td>
                <td>${results.total_events}</td>
            </tr>`;
        }
        tableHtml += `</table>`;
        document.getElementById('resultsTable').innerHTML = tableHtml;

        // Show the results section
        document.getElementById('resultSection').style.display = 'block';
    } catch (error) {
        console.error('Analysis failed:', error);
        alert('Failed to analyze operation. Check console for details.');
    }
}

async function checkSIEMStatus() {
    try {
        const response = await fetch('/plugin/detmeter/api/status');
        const status = await response.json();
        let html = `<h3>SIEM Connection Status</h3><div style="display:flex; flex-wrap:wrap; gap:10px;">`;
        for (const [siem, info] of Object.entries(status)) {
            const badgeClass = info.status === 'reachable' ? 'status-up' : 'status-down';
            html += `<div style="border:1px solid #ddd; padding:15px; border-radius:5px; min-width:200px;">
                <h4 style="margin-top:0;">${siem.toUpperCase()}</h4>
                <p><strong>Status:</strong> <span class="status-badge ${badgeClass}">${info.status}</span></p>
                <p><strong>Endpoint:</strong><br><code style="font-size:0.8em;">${info.endpoint}</code></p>
                <p><strong>Enabled:</strong> ${info.enabled ? 'Yes' : 'No'}</p>
            </div>`;
        }
        html += `</div>`;
        document.getElementById('statusDisplay').innerHTML = html;
    } catch (error) {
        document.getElementById('statusDisplay').innerHTML = `<p style="color:red;">Error fetching status: ${error.message}</p>`;
    }
}
