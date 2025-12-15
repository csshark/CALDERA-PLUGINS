"""
DetMeter API Endpoints
"""
import os
import json
from aiohttp import web
import logging

class DetMeterApi:
    def __init__(self, services, detmeter_svc=None):
        self.services = services
        self.data_svc = services.get('data_svc')
        self.detmeter_svc = detmeter_svc
        self.log = logging.getLogger('detmeter_api')
        
        # Setup paths
        self.plugin_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.static_dir = os.path.join(self.plugin_dir, 'static')
        
        # Ensure static directory exists
        os.makedirs(self.static_dir, exist_ok=True)
        
        # Create default HTML if not exists
        self._create_default_html()

    def _create_default_html(self):
        """Create default HTML interface"""
        html_path = os.path.join(self.static_dir, 'index.html')
        if not os.path.exists(html_path):
            html_content = """
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>DetMeter - SIEM Detection Analysis</title>
                <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
                <style>
                    * { margin: 0; padding: 0; box-sizing: border-box; }
                    body {
                        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
                        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                        min-height: 100vh;
                        padding: 20px;
                    }
                    .container {
                        max-width: 1200px;
                        margin: 0 auto;
                        background: white;
                        border-radius: 15px;
                        box-shadow: 0 20px 60px rgba(0,0,0,0.3);
                        overflow: hidden;
                    }
                    .header {
                        background: linear-gradient(135deg, #2c3e50 0%, #4a6491 100%);
                        color: white;
                        padding: 30px;
                        text-align: center;
                    }
                    .header h1 {
                        font-size: 2.5em;
                        margin-bottom: 10px;
                        display: flex;
                        align-items: center;
                        justify-content: center;
                        gap: 15px;
                    }
                    .header h1 i {
                        font-size: 1.2em;
                    }
                    .content {
                        padding: 30px;
                    }
                    .card {
                        background: #f8f9fa;
                        border-radius: 10px;
                        padding: 25px;
                        margin-bottom: 25px;
                        border: 1px solid #e9ecef;
                        box-shadow: 0 4px 6px rgba(0,0,0,0.05);
                    }
                    .card h2 {
                        color: #2c3e50;
                        margin-bottom: 20px;
                        padding-bottom: 10px;
                        border-bottom: 2px solid #3498db;
                    }
                    .input-group {
                        display: flex;
                        gap: 15px;
                        margin-bottom: 20px;
                        flex-wrap: wrap;
                    }
                    .input-group input, .input-group select {
                        flex: 1;
                        min-width: 200px;
                        padding: 12px 15px;
                        border: 2px solid #ddd;
                        border-radius: 8px;
                        font-size: 16px;
                        transition: border-color 0.3s;
                    }
                    .input-group input:focus, .input-group select:focus {
                        border-color: #3498db;
                        outline: none;
                    }
                    .btn {
                        background: linear-gradient(135deg, #3498db 0%, #2980b9 100%);
                        color: white;
                        border: none;
                        padding: 12px 30px;
                        border-radius: 8px;
                        font-size: 16px;
                        font-weight: 600;
                        cursor: pointer;
                        transition: transform 0.2s, box-shadow 0.2s;
                        display: inline-flex;
                        align-items: center;
                        gap: 10px;
                    }
                    .btn:hover {
                        transform: translateY(-2px);
                        box-shadow: 0 5px 15px rgba(52, 152, 219, 0.4);
                    }
                    .btn:active {
                        transform: translateY(0);
                    }
                    .btn-secondary {
                        background: linear-gradient(135deg, #95a5a6 0%, #7f8c8d 100%);
                    }
                    .btn-success {
                        background: linear-gradient(135deg, #27ae60 0%, #219653 100%);
                    }
                    .btn-danger {
                        background: linear-gradient(135deg, #e74c3c 0%, #c0392b 100%);
                    }
                    .operation-list {
                        max-height: 300px;
                        overflow-y: auto;
                        margin: 15px 0;
                        border: 1px solid #ddd;
                        border-radius: 8px;
                    }
                    .operation-item {
                        padding: 15px;
                        border-bottom: 1px solid #eee;
                        cursor: pointer;
                        transition: background 0.2s;
                        display: flex;
                        justify-content: space-between;
                        align-items: center;
                    }
                    .operation-item:hover {
                        background: #e3f2fd;
                    }
                    .operation-item.selected {
                        background: #bbdefb;
                        border-left: 4px solid #2196f3;
                    }
                    .operation-info {
                        display: flex;
                        flex-direction: column;
                        gap: 5px;
                    }
                    .operation-name {
                        font-weight: 600;
                        color: #2c3e50;
                    }
                    .operation-details {
                        font-size: 0.9em;
                        color: #666;
                    }
                    .chart-container {
                        height: 400px;
                        margin: 30px 0;
                        position: relative;
                    }
                    .results-grid {
                        display: grid;
                        grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
                        gap: 20px;
                        margin-top: 30px;
                    }
                    .result-card {
                        background: white;
                        border-radius: 10px;
                        padding: 20px;
                        border: 1px solid #e0e0e0;
                        box-shadow: 0 2px 4px rgba(0,0,0,0.05);
                    }
                    .siem-header {
                        display: flex;
                        justify-content: space-between;
                        align-items: center;
                        margin-bottom: 15px;
                        padding-bottom: 10px;
                        border-bottom: 1px solid #eee;
                    }
                    .siem-name {
                        font-weight: 700;
                        font-size: 1.2em;
                        color: #2c3e50;
                    }
                    .detection-rate {
                        font-size: 1.5em;
                        font-weight: 700;
                    }
                    .rate-high { color: #27ae60; }
                    .rate-medium { color: #f39c12; }
                    .rate-low { color: #e74c3c; }
                    .technique-list {
                        margin-top: 10px;
                        max-height: 150px;
                        overflow-y: auto;
                    }
                    .technique-item {
                        padding: 5px 10px;
                        background: #f8f9fa;
                        margin: 2px 0;
                        border-radius: 4px;
                        font-size: 0.9em;
                    }
                    .loading {
                        display: none;
                        text-align: center;
                        padding: 40px;
                    }
                    .loading.active {
                        display: block;
                    }
                    .spinner {
                        border: 4px solid #f3f3f3;
                        border-top: 4px solid #3498db;
                        border-radius: 50%;
                        width: 40px;
                        height: 40px;
                        animation: spin 1s linear infinite;
                        margin: 0 auto 20px;
                    }
                    @keyframes spin {
                        0% { transform: rotate(0deg); }
                        100% { transform: rotate(360deg); }
                    }
                    .alert {
                        padding: 15px;
                        border-radius: 8px;
                        margin: 15px 0;
                        display: none;
                    }
                    .alert-success {
                        background: #d4edda;
                        color: #155724;
                        border: 1px solid #c3e6cb;
                    }
                    .alert-error {
                        background: #f8d7da;
                        color: #721c24;
                        border: 1px solid #f5c6cb;
                    }
                    .alert-info {
                        background: #d1ecf1;
                        color: #0c5460;
                        border: 1px solid #bee5eb;
                    }
                    .tab-container {
                        display: flex;
                        border-bottom: 2px solid #eee;
                        margin-bottom: 20px;
                    }
                    .tab {
                        padding: 12px 25px;
                        cursor: pointer;
                        font-weight: 600;
                        color: #666;
                        border-bottom: 3px solid transparent;
                        transition: all 0.3s;
                    }
                    .tab:hover {
                        color: #3498db;
                    }
                    .tab.active {
                        color: #3498db;
                        border-bottom-color: #3498db;
                    }
                    .tab-content {
                        display: none;
                    }
                    .tab-content.active {
                        display: block;
                    }
                    .status-badge {
                        padding: 4px 12px;
                        border-radius: 20px;
                        font-size: 0.85em;
                        font-weight: 600;
                    }
                    .status-online { background: #d4edda; color: #155724; }
                    .status-offline { background: #f8d7da; color: #721c24; }
                    .status-disabled { background: #f8f9fa; color: #6c757d; }
                    @media (max-width: 768px) {
                        .container { border-radius: 0; }
                        .content { padding: 20px; }
                        .input-group { flex-direction: column; }
                        .input-group input, .input-group select { width: 100%; }
                        .results-grid { grid-template-columns: 1fr; }
                    }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>
                            <span style="font-size: 1.2em;">🔍</span>
                            DetMeter - SIEM Detection Analyzer
                        </h1>
                        <p>Compare detection effectiveness across multiple SIEM systems</p>
                    </div>
                    
                    <div class="content">
                        <div class="tab-container">
                            <div class="tab active" onclick="switchTab('analyze')">📊 Analyze Operation</div>
                            <div class="tab" onclick="switchTab('status')">🔍 SIEM Status</div>
                            <div class="tab" onclick="switchTab('techniques')">🎯 MITRE Techniques</div>
                        </div>
                        
                        <!-- Analysis Tab -->
                        <div id="analyze-tab" class="tab-content active">
                            <div class="card">
                                <h2>Select Operation</h2>
                                <div class="input-group">
                                    <select id="operationSelect">
                                        <option value="">Loading operations...</option>
                                    </select>
                                    <button class="btn" onclick="refreshOperations()">
                                        <span>🔄</span> Refresh
                                    </button>
                                </div>
                                
                                <div id="operationsContainer" class="operation-list"></div>
                                
                                <div style="margin-top: 20px;">
                                    <button class="btn btn-success" onclick="analyzeOperation()" id="analyzeBtn" disabled>
                                        <span>📈</span> Analyze Detection
                                    </button>
                                    <button class="btn btn-secondary" onclick="clearResults()">
                                        <span>🗑️</span> Clear Results
                                    </button>
                                </div>
                            </div>
                            
                            <div id="resultsContainer" style="display: none;">
                                <div class="card">
                                    <h2>Detection Results</h2>
                                    <div id="operationInfo"></div>
                                    
                                    <div class="chart-container">
                                        <canvas id="detectionChart"></canvas>
                                    </div>
                                    
                                    <div class="results-grid" id="siemResults"></div>
                                </div>
                            </div>
                        </div>
                        
                        <!-- Status Tab -->
                        <div id="status-tab" class="tab-content">
                            <div class="card">
                                <h2>SIEM Connection Status</h2>
                                <button class="btn" onclick="checkSIEMStatus()">
                                    <span>🔍</span> Check Status
                                </button>
                                <div id="statusResults" style="margin-top: 20px;"></div>
                            </div>
                        </div>
                        
                        <!-- Techniques Tab -->
                        <div id="techniques-tab" class="tab-content">
                            <div class="card">
                                <h2>MITRE ATT&CK Techniques</h2>
                                <div id="techniquesList"></div>
                            </div>
                        </div>
                    </div>
                    
                    <!-- Loading overlay -->
                    <div id="loading" class="loading">
                        <div class="spinner"></div>
                        <p>Processing request...</p>
                    </div>
                    
                    <!-- Alert messages -->
                    <div id="alertContainer" style="position: fixed; top: 20px; right: 20px; width: 300px; z-index: 1000;"></div>
                </div>

                <script>
                    let currentOperation = null;
                    let detectionChart = null;
                    
                    // Initialize on load
                    document.addEventListener('DOMContentLoaded', function() {
                        loadOperations();
                        loadTechniques();
                    });
                    
                    function switchTab(tabName) {
                        // Update tabs
                        document.querySelectorAll('.tab').forEach(tab => {
                            tab.classList.remove('active');
                        });
                        document.querySelectorAll('.tab-content').forEach(content => {
                            content.classList.remove('active');
                        });
                        
                        // Activate selected tab
                        document.querySelector(`.tab[onclick="switchTab('${tabName}')"]`).classList.add('active');
                        document.getElementById(`${tabName}-tab`).classList.add('active');
                    }
                    
                    async function loadOperations() {
                        showLoading();
                        try {
                            const response = await fetch('/detmeter/api/operations');
                            const operations = await response.json();
                            
                            const select = document.getElementById('operationSelect');
                            const container = document.getElementById('operationsContainer');
                            
                            select.innerHTML = '<option value="">Select an operation...</option>';
                            container.innerHTML = '';
                            
                            operations.forEach(op => {
                                // Add to select
                                const option = document.createElement('option');
                                option.value = op.id;
                                option.textContent = `${op.name} (${op.id})`;
                                select.appendChild(option);
                                
                                // Add to list
                                const item = document.createElement('div');
                                item.className = 'operation-item';
                                item.dataset.id = op.id;
                                item.innerHTML = `
                                    <div class="operation-info">
                                        <div class="operation-name">${op.name}</div>
                                        <div class="operation-details">
                                            ID: ${op.id} | Start: ${new Date(op.start).toLocaleDateString()} | 
                                            Techniques: ${op.technique_count || 0}
                                        </div>
                                    </div>
                                    <button class="btn" style="padding: 8px 16px;" onclick="selectOperation('${op.id}')">
                                        Select
                                    </button>
                                `;
                                container.appendChild(item);
                            });
                            
                        } catch (error) {
                            showAlert('Error loading operations: ' + error.message, 'error');
                        } finally {
                            hideLoading();
                        }
                    }
                    
                    function selectOperation(operationId) {
                        currentOperation = operationId;
                        
                        // Update UI
                        document.querySelectorAll('.operation-item').forEach(item => {
                            item.classList.remove('selected');
                            if (item.dataset.id === operationId) {
                                item.classList.add('selected');
                            }
                        });
                        
                        // Enable analyze button
                        document.getElementById('analyzeBtn').disabled = false;
                        
                        // Update select
                        document.getElementById('operationSelect').value = operationId;
                        
                        showAlert(`Operation ${operationId} selected`, 'success');
                    }
                    
                    async function analyzeOperation() {
                        if (!currentOperation) {
                            showAlert('Please select an operation first', 'error');
                            return;
                        }
                        
                        showLoading();
                        try {
                            const response = await fetch('/detmeter/api/analyze', {
                                method: 'POST',
                                headers: { 'Content-Type': 'application/json' },
                                body: JSON.stringify({ operation_id: currentOperation })
                            });
                            
                            const result = await response.json();
                            
                            if (result.error) {
                                showAlert('Analysis error: ' + result.error, 'error');
                                return;
                            }
                            
                            displayResults(result);
                            
                        } catch (error) {
                            showAlert('Analysis failed: ' + error.message, 'error');
                        } finally {
                            hideLoading();
                        }
                    }
                    
                    function displayResults(data) {
                        // Show results container
                        document.getElementById('resultsContainer').style.display = 'block';
                        
                        // Update operation info
                        document.getElementById('operationInfo').innerHTML = `
                            <div style="background: #f8f9fa; padding: 15px; border-radius: 8px; margin-bottom: 20px;">
                                <h3 style="margin-top: 0; color: #2c3e50;">${data.operation_name}</h3>
                                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 10px; margin-top: 10px;">
                                    <div><strong>Operation ID:</strong> ${data.operation_id}</div>
                                    <div><strong>Techniques:</strong> ${data.techniques_used.list.length}</div>
                                    <div><strong>Analysis Time:</strong> ${new Date(data.analysis_time).toLocaleString()}</div>
                                    <div><strong>SIEMs Tested:</strong> ${Object.keys(data.siem_results).length}</div>
                                </div>
                            </div>
                        `;
                        
                        // Prepare chart data
                        const siemNames = [];
                        const detectionRates = [];
                        const colors = [];
                        
                        for (const [siem, results] of Object.entries(data.siem_results)) {
                            siemNames.push(siem.toUpperCase());
                            detectionRates.push(results.detection_rate);
                            
                            // Color based on detection rate
                            if (results.detection_rate >= 70) colors.push('#27ae60');
                            else if (results.detection_rate >= 40) colors.push('#f39c12');
                            else colors.push('#e74c3c');
                        }
                        
                        // Create or update chart
                        const ctx = document.getElementById('detectionChart').getContext('2d');
                        if (detectionChart) {
                            detectionChart.destroy();
                        }
                        
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
                                        ticks: {
                                            callback: function(value) {
                                                return value + '%';
                                            }
                                        },
                                        title: {
                                            display: true,
                                            text: 'Detection Rate'
                                        }
                                    },
                                    x: {
                                        title: {
                                            display: true,
                                            text: 'SIEM System'
                                        }
                                    }
                                },
                                plugins: {
                                    tooltip: {
                                        callbacks: {
                                            label: function(context) {
                                                return `Detection: ${context.parsed.y}%`;
                                            }
                                        }
                                    }
                                }
                            }
                        });
                        
                        // Display detailed results
                        const resultsGrid = document.getElementById('siemResults');
                        resultsGrid.innerHTML = '';
                        
                        for (const [siem, results] of Object.entries(data.siem_results)) {
                            const rateClass = results.detection_rate >= 70 ? 'rate-high' : 
                                            results.detection_rate >= 40 ? 'rate-medium' : 'rate-low';
                            
                            const card = document.createElement('div');
                            card.className = 'result-card';
                            card.innerHTML = `
                                <div class="siem-header">
                                    <div class="siem-name">${siem.toUpperCase()}</div>
                                    <div class="detection-rate ${rateClass}">${results.detection_rate}%</div>
                                </div>
                                <div><strong>Events Found:</strong> ${results.events_found}</div>
                                <div><strong>Techniques Detected:</strong> ${results.techniques_detected.length}/${data.techniques_used.list.length}</div>
                                ${results.query_time ? `<div><strong>Query Time:</strong> ${results.query_time.toFixed(2)}s</div>` : ''}
                                <div class="technique-list" style="margin-top: 10px;">
                                    ${results.techniques_detected.map(t => 
                                        `<div class="technique-item">${t}</div>`
                                    ).join('')}
                                </div>
                            `;
                            resultsGrid.appendChild(card);
                        }
                        
                        showAlert('Analysis completed successfully', 'success');
                    }
                    
                    async function checkSIEMStatus() {
                        showLoading();
                        try {
                            const response = await fetch('/detmeter/api/status');
                            const status = await response.json();
                            
                            const container = document.getElementById('statusResults');
                            container.innerHTML = '<div class="results-grid">';
                            
                            for (const [siem, info] of Object.entries(status)) {
                                const statusClass = info.status === 'reachable' ? 'status-online' : 
                                                  info.status === 'disabled' ? 'status-disabled' : 'status-offline';
                                
                                container.innerHTML += `
                                    <div class="result-card">
                                        <div class="siem-header">
                                            <div class="siem-name">${siem.toUpperCase()}</div>
                                            <span class="status-badge ${statusClass}">${info.status}</span>
                                        </div>
                                        <div><strong>Type:</strong> ${info.type}</div>
                                        <div><strong>Enabled:</strong> ${info.enabled ? 'Yes' : 'No'}</div>
                                        <div><strong>Endpoint:</strong><br><small>${info.endpoint}</small></div>
                                        ${info.reachable !== undefined ? `<div><strong>Reachable:</strong> ${info.reachable ? 'Yes' : 'No'}</div>` : ''}
                                        ${info.response_time ? `<div><strong>Response Time:</strong> ${info.response_time.toFixed(2)}s</div>` : ''}
                                        ${info.version ? `<div><strong>Version:</strong> ${info.version}</div>` : ''}
                                        ${info.last_check ? `<div><strong>Last Check:</strong> ${new Date(info.last_check).toLocaleTimeString()}</div>` : ''}
                                    </div>
                                `;
                            }
                            
                            container.innerHTML += '</div>';
                            
                        } catch (error) {
                            showAlert('Status check failed: ' + error.message, 'error');
                        } finally {
                            hideLoading();
                        }
                    }
                    
                    async function loadTechniques() {
                        try {
                            const response = await fetch('/detmeter/api/techniques');
                            const techniques = await response.json();
                            
                            const container = document.getElementById('techniquesList');
                            if (techniques.length === 0) {
                                container.innerHTML = '<p>No techniques loaded</p>';
                                return;
                            }
                            
                            container.innerHTML = '<div class="results-grid">';
                            
                            techniques.forEach(tech => {
                                container.innerHTML += `
                                    <div class="result-card">
                                        <div class="siem-header">
                                            <div class="siem-name">${tech.id}</div>
                                        </div>
                                        <div><strong>${tech.name}</strong></div>
                                        <div><strong>Tactics:</strong> ${tech.tactics.join(', ')}</div>
                                    </div>
                                `;
                            });
                            
                            container.innerHTML += '</div>';
                            
                        } catch (error) {
                            document.getElementById('techniquesList').innerHTML = 
                                '<p style="color: #e74c3c;">Error loading techniques</p>';
                        }
                    }
                    
                    function refreshOperations() {
                        loadOperations();
                    }
                    
                    function clearResults() {
                        document.getElementById('resultsContainer').style.display = 'none';
                        document.getElementById('operationsContainer').innerHTML = '';
                        document.getElementById('operationSelect').value = '';
                        currentOperation = null;
                        document.getElementById('analyzeBtn').disabled = true;
                        
                        if (detectionChart) {
                            detectionChart.destroy();
                            detectionChart = null;
                        }
                        
                        showAlert('Results cleared', 'info');
                    }
                    
                    function showLoading() {
                        document.getElementById('loading').classList.add('active');
                    }
                    
                    function hideLoading() {
                        document.getElementById('loading').classList.remove('active');
                    }
                    
                    function showAlert(message, type = 'info') {
                        const container = document.getElementById('alertContainer');
                        const alert = document.createElement('div');
                        alert.className = `alert alert-${type}`;
                        alert.innerHTML = `
                            <div style="display: flex; justify-content: space-between; align-items: center;">
                                <span>${message}</span>
                                <button onclick="this.parentElement.parentElement.remove()" style="background: none; border: none; cursor: pointer; font-size: 20px;">
                                    &times;
                                </button>
                            </div>
                        `;
                        
                        container.appendChild(alert);
                        
                        // Auto-remove after 5 seconds
                        setTimeout(() => {
                            if (alert.parentElement) {
                                alert.remove();
                            }
                        }, 5000);
                    }
                </script>
            </body>
            </html>
            """
            
            with open(html_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            self.log.info(f"Created default HTML interface at {html_path}")

    async def gui(self, request):
        """Serve the main GUI interface"""
        try:
            html_path = os.path.join(self.static_dir, 'index.html')
            with open(html_path, 'r', encoding='utf-8') as f:
                html_content = f.read()
            
            return web.Response(text=html_content, content_type='text/html')
            
        except FileNotFoundError:
            return web.Response(
                text='<h1>DetMeter</h1><p>Interface not found. Please check plugin installation.</p>',
                content_type='text/html'
            )

    async def serve_static(self, request):
        """Serve static files"""
        path = request.match_info['path']
        file_path = os.path.join(self.static_dir, path)
        
        if os.path.exists(file_path) and os.path.isfile(file_path):
            return web.FileResponse(file_path)
        return web.Response(status=404)

    async def analyze_operation(self, request):
        """Analyze operation detection"""
        try:
            if not self.detmeter_svc:
                return web.json_response({'error': 'DetMeter service not available'}, status=500)
            
            data = await request.json()
            operation_id = data.get('operation_id')
            
            if not operation_id:
                return web.json_response({'error': 'Operation ID is required'}, status=400)
            
            # Optional parameters
            timeframe = data.get('timeframe_hours')
            
            # Perform analysis
            result = await self.detmeter_svc.analyze_operation(operation_id, timeframe)
            
            return web.json_response(result)
            
        except json.JSONDecodeError:
            return web.json_response({'error': 'Invalid JSON data'}, status=400)
        except Exception as e:
            self.log.error(f"Error in analyze_operation: {str(e)}")
            return web.json_response({'error': str(e)}, status=500)

    async def get_siem_status(self, request):
        """Get SIEM connection status"""
        try:
            if not self.detmeter_svc:
                return web.json_response({'error': 'DetMeter service not available'}, status=500)
            
            status = await self.detmeter_svc.get_siem_status()
            return web.json_response(status)
            
        except Exception as e:
            self.log.error(f"Error in get_siem_status: {str(e)}")
            return web.json_response({'error': str(e)}, status=500)

    async def get_operations(self, request):
        """Get list of available operations"""
        try:
            # Get all operations
            operations = await self.data_svc.locate('operations')
            
            # Format response
            formatted_ops = []
            for op in operations:
                if hasattr(op, 'id') and op.id:
                    # Get technique count if detmeter service is available
                    tech_count = 0
                    if self.detmeter_svc:
                        techniques = await self.detmeter_svc._extract_techniques_with_details(op)
                        tech_count = len(techniques)
                    
                    formatted_ops.append({
                        'id': op.id,
                        'name': getattr(op, 'name', 'Unnamed Operation'),
                        'start': getattr(op, 'start', None),
                        'finish': getattr(op, 'finish', None),
                        'state': getattr(op, 'state', 'unknown'),
                        'technique_count': tech_count
                    })
            
            return web.json_response(formatted_ops)
            
        except Exception as e:
            self.log.error(f"Error in get_operations: {str(e)}")
            return web.json_response({'error': str(e)}, status=500)

    async def get_techniques(self, request):
        """Get list of known MITRE techniques"""
        try:
            if not self.detmeter_svc:
                return web.json_response([], status=200)
            
            # Get techniques from the service
            techniques = []
            mitre_data = getattr(self.detmeter_svc, 'mitre_techniques', {})
            
            for tech_id, info in mitre_data.items():
                techniques.append({
                    'id': tech_id,
                    'name': info.get('name', 'Unknown'),
                    'tactics': info.get('tactics', [])
                })
            
            return web.json_response(techniques)
            
        except Exception as e:
            self.log.error(f"Error in get_techniques: {str(e)}")
            return web.json_response([], status=200)

    async def health_check(self, request):
        """Health check endpoint"""
        status = {
            'status': 'healthy',
            'plugin': 'detmeter',
            'version': '1.0.0',
            'services': {
                'detmeter_svc': self.detmeter_svc is not None,
                'data_svc': self.data_svc is not None
            },
            'timestamp': datetime.now().isoformat() if hasattr(datetime, 'now') else 'N/A'
        }
        return web.json_response(status)
