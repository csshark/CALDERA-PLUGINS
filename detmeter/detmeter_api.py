"""
DetMeter API Endpoints - Updated for new Caldera UI
"""
import os
import json
from aiohttp import web
import logging

class DetMeterApi:
    def __init__(self, detmeter_svc, services):
        self.svc = detmeter_svc
        self.services = services
        self.data_svc = services.get('data_svc')
        self.log = logging.getLogger('detmeter_api')
        self.plugin_path = 'plugins/detmeter'
        self.static_path = os.path.join(self.plugin_path, 'static')
        
    async def serve_ui_wrapper(self, request):
        """Serve UI wrapper for Caldera's new interface"""
        try:
            # Get the main Caldera UI and inject our component
            html_content = """
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>DetMeter - SIEM Detection Comparison</title>
                <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
                <style>
                    body {
                        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
                        margin: 0;
                        padding: 20px;
                        background-color: #f5f7fa;
                        color: #333;
                    }
                    .header {
                        background: linear-gradient(135deg, #2c3e50, #4a6491);
                        color: white;
                        padding: 25px;
                        border-radius: 10px;
                        margin-bottom: 30px;
                        box-shadow: 0 4px 12px rgba(0,0,0,0.1);
                    }
                    .container {
                        max-width: 1400px;
                        margin: 0 auto;
                    }
                    .card {
                        background: white;
                        border-radius: 10px;
                        padding: 25px;
                        margin-bottom: 25px;
                        box-shadow: 0 2px 8px rgba(0,0,0,0.08);
                        border: 1px solid #e1e5eb;
                    }
                    .btn {
                        background: #3498db;
                        color: white;
                        border: none;
                        padding: 12px 24px;
                        border-radius: 6px;
                        cursor: pointer;
                        font-size: 16px;
                        font-weight: 500;
                        transition: background 0.3s;
                        margin: 5px;
                    }
                    .btn:hover {
                        background: #2980b9;
                    }
                    .btn-secondary {
                        background: #7f8c8d;
                    }
                    .btn-secondary:hover {
                        background: #6c7b7d;
                    }
                    input, select {
                        padding: 12px;
                        border: 2px solid #ddd;
                        border-radius: 6px;
                        font-size: 16px;
                        margin: 5px;
                        transition: border-color 0.3s;
                    }
                    input:focus, select:focus {
                        border-color: #3498db;
                        outline: none;
                    }
                    .chart-container {
                        background: white;
                        padding: 20px;
                        border-radius: 8px;
                        margin: 20px 0;
                        height: 500px;
                        position: relative;
                    }
                    .status-grid {
                        display: grid;
                        grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
                        gap: 20px;
                        margin-top: 20px;
                    }
                    .status-card {
                        background: #f8f9fa;
                        border-left: 4px solid #3498db;
                        padding: 15px;
                        border-radius: 6px;
                    }
                    .status-up {
                        border-left-color: #27ae60;
                    }
                    .status-down {
                        border-left-color: #e74c3c;
                    }
                    .operation-list {
                        max-height: 300px;
                        overflow-y: auto;
                        border: 1px solid #ddd;
                        border-radius: 6px;
                        margin: 15px 0;
                    }
                    .operation-item {
                        padding: 12px;
                        border-bottom: 1px solid #eee;
                        cursor: pointer;
                        transition: background 0.2s;
                    }
                    .operation-item:hover {
                        background: #f8f9fa;
                    }
                    .operation-item.selected {
                        background: #e3f2fd;
                        border-left: 3px solid #3498db;
                    }
                    .results-table {
                        width: 100%;
                        border-collapse: collapse;
                        margin-top: 25px;
                    }
                    .results-table th {
                        background: #f8f9fa;
                        padding: 15px;
                        text-align: left;
                        border-bottom: 2px solid #dee2e6;
                        font-weight: 600;
                    }
                    .results-table td {
                        padding: 15px;
                        border-bottom: 1px solid #eee;
                    }
                    .results-table tr:hover {
                        background: #f8f9fa;
                    }
                    .detection-badge {
                        display: inline-block;
                        padding: 4px 12px;
                        border-radius: 20px;
                        font-size: 14px;
                        font-weight: 500;
                    }
                    .detection-high {
                        background: #d4edda;
                        color: #155724;
                    }
                    .detection-medium {
                        background: #fff3cd;
                        color: #856404;
                    }
                    .detection-low {
                        background: #f8d7da;
                        color: #721c24;
                    }
                    .loading {
                        text-align: center;
                        padding: 40px;
                        color: #6c757d;
                    }
                    .loading-spinner {
                        border: 3px solid #f3f3f3;
                        border-top: 3px solid #3498db;
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
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1 style="margin: 0 0 10px 0;">🔍 DetMeter</h1>
                        <p style="margin: 0; opacity: 0.9;">Porównaj wykrywalność różnych systemów SIEM dla operacji Caldera</p>
                    </div>
                    
                    <div class="card">
                        <h2>🏹 Wybierz Operację</h2>
                        <div style="display: flex; align-items: center; flex-wrap: wrap; margin-bottom: 15px;">
                            <button class="btn" onclick="loadOperations()">⟳ Odśwież listę operacji</button>
                            <input type="text" id="operationSearch" placeholder="Szukaj operacji..." 
                                   onkeyup="filterOperations()" style="flex-grow: 1; max-width: 400px;">
                        </div>
                        
                        <div id="operationsLoading" class="loading">
                            <div class="loading-spinner"></div>
                            <p>Ładowanie listy operacji...</p>
                        </div>
                        
                        <div id="operationsList" class="operation-list" style="display: none;"></div>
                        
                        <div style="margin-top: 20px;">
                            <button class="btn" onclick="analyzeSelectedOperation()" id="analyzeBtn" disabled>
                                📊 Analizuj wykrywalność
                            </button>
                            <button class="btn btn-secondary" onclick="checkSIEMStatus()">
                                🔍 Sprawdź status SIEM
                            </button>
                        </div>
                    </div>
                    
                    <div id="statusDisplay" style="display: none;"></div>
                    
                    <div id="resultsSection" style="display: none;">
                        <div class="card">
                            <h2>📊 Wyniki Analizy Wykrywalności</h2>
                            <div id="operationInfo" style="margin-bottom: 20px;"></div>
                            
                            <div id="resultsLoading" class="loading" style="display: none;">
                                <div class="loading-spinner"></div>
                                <p>Analizowanie wykrywalności...</p>
                            </div>
                            
                            <div class="chart-container">
                                <canvas id="detectionChart"></canvas>
                            </div>
                            
                            <div id="resultsTable"></div>
                        </div>
                    </div>
                </div>

                <script>
                    let currentOperationId = null;
                    let detectionChart = null;
                    let allOperations = [];
                    
                    // Ładuj listę operacji przy starcie
                    document.addEventListener('DOMContentLoaded', loadOperations);
                    
                    async function loadOperations() {
                        const loadingDiv = document.getElementById('operationsLoading');
                        const listDiv = document.getElementById('operationsList');
                        
                        loadingDiv.style.display = 'block';
                        listDiv.style.display = 'none';
                        
                        try {
                            const response = await fetch('/plugin/detmeter/api/operations');
                            const operations = await response.json();
                            allOperations = operations;
                            
                            displayOperations(operations);
                            loadingDiv.style.display = 'none';
                            listDiv.style.display = 'block';
                            
                        } catch (error) {
                            console.error('Błąd ładowania operacji:', error);
                            loadingDiv.innerHTML = '<p style="color: #e74c3c;">❌ Błąd ładowania operacji</p>';
                        }
                    }
                    
                    function displayOperations(operations) {
                        const listDiv = document.getElementById('operationsList');
                        
                        if (!operations || operations.length === 0) {
                            listDiv.innerHTML = '<div style="padding: 20px; text-align: center; color: #6c757d;">Brak dostępnych operacji</div>';
                            return;
                        }
                        
                        let html = '';
                        operations.forEach(op => {
                            const opDate = op.start ? new Date(op.start).toLocaleDateString() : 'Brak daty';
                            html += `
                                <div class="operation-item" data-id="${op.id}" onclick="selectOperation('${op.id}')">
                                    <strong>${op.name || op.id}</strong><br>
                                    <small style="color: #6c757d;">
                                        ID: ${op.id} | Start: ${opDate} | Techniki: ${op.technique_count || 0}
                                    </small>
                                </div>
                            `;
                        });
                        
                        listDiv.innerHTML = html;
                    }
                    
                    function filterOperations() {
                        const searchTerm = document.getElementById('operationSearch').value.toLowerCase();
                        const filtered = allOperations.filter(op => 
                            (op.name && op.name.toLowerCase().includes(searchTerm)) || 
                            op.id.toLowerCase().includes(searchTerm)
                        );
                        displayOperations(filtered);
                    }
                    
                    function selectOperation(operationId) {
                        currentOperationId = operationId;
                        
                        // Update UI
                        document.querySelectorAll('.operation-item').forEach(item => {
                            item.classList.remove('selected');
                            if (item.dataset.id === operationId) {
                                item.classList.add('selected');
                            }
                        });
                        
                        // Enable analyze button
                        document.getElementById('analyzeBtn').disabled = false;
                        document.getElementById('analyzeBtn').innerHTML = `📊 Analizuj: ${operationId}`;
                        
                        // Hide previous results
                        document.getElementById('resultsSection').style.display = 'none';
                    }
                    
                    async function analyzeSelectedOperation() {
                        if (!currentOperationId) {
                            alert('Proszę wybrać operację z listy.');
                            return;
                        }
                        
                        const resultsSection = document.getElementById('resultsSection');
                        const resultsLoading = document.getElementById('resultsLoading');
                        const operationInfo = document.getElementById('operationInfo');
                        
                        resultsSection.style.display = 'block';
                        resultsLoading.style.display = 'block';
                        
                        try {
                            const response = await fetch('/plugin/detmeter/api/analyze', {
                                method: 'POST',
                                headers: { 'Content-Type': 'application/json' },
                                body: JSON.stringify({ operation_id: currentOperationId })
                            });
                            
                            const data = await response.json();
                            
                            if (data.error) {
                                alert('Błąd: ' + data.error);
                                resultsLoading.style.display = 'none';
                                return;
                            }
                            
                            // Display operation info
                            operationInfo.innerHTML = `
                                <div style="background: #f8f9fa; padding: 15px; border-radius: 6px;">
                                    <h3 style="margin-top: 0;">${data.operation_name}</h3>
                                    <p><strong>ID operacji:</strong> ${data.operation_id}</p>
                                    <p><strong>Techniki MITRE ATT&CK użyte:</strong> ${data.techniques_used.length}</p>
                                    <p><strong>Czas analizy:</strong> ${new Date(data.analysis_time).toLocaleString()}</p>
                                </div>
                            `;
                            
                            // Create chart
                            createDetectionChart(data);
                            
                            // Create results table
                            createResultsTable(data);
                            
                            resultsLoading.style.display = 'none';
                            
                        } catch (error) {
                            console.error('Błąd analizy:', error);
                            resultsLoading.innerHTML = '<p style="color: #e74c3c;">❌ Błąd podczas analizy</p>';
                        }
                    }
                    
                    function createDetectionChart(data) {
                        const siemNames = Object.keys(data.siem_results);
                        const detectionRates = siemNames.map(name => 
                            parseFloat(data.siem_results[name].detection_rate.toFixed(1))
                        );
                        
                        // Assign colors based on detection rate
                        const colors = detectionRates.map(rate => {
                            if (rate >= 70) return '#27ae60'; // Green
                            if (rate >= 40) return '#f39c12'; // Orange
                            return '#e74c3c'; // Red
                        });
                        
                        const ctx = document.getElementById('detectionChart').getContext('2d');
                        
                        // Destroy existing chart
                        if (detectionChart) {
                            detectionChart.destroy();
                        }
                        
                        detectionChart = new Chart(ctx, {
                            type: 'bar',
                            data: {
                                labels: siemNames,
                                datasets: [{
                                    label: 'Wskaźnik wykrywalności (%)',
                                    data: detectionRates,
                                    backgroundColor: colors,
                                    borderColor: colors,
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
                                        title: {
                                            display: true,
                                            text: 'Wskaźnik wykrywalności (%)',
                                            font: { size: 14, weight: 'bold' }
                                        },
                                        ticks: {
                                            callback: function(value) {
                                                return value + '%';
                                            }
                                        }
                                    },
                                    x: {
                                        title: {
                                            display: true,
                                            text: 'System SIEM',
                                            font: { size: 14, weight: 'bold' }
                                        }
                                    }
                                },
                                plugins: {
                                    legend: { display: false },
                                    tooltip: {
                                        callbacks: {
                                            label: function(context) {
                                                return `Wykrywalność: ${context.parsed.y}%`;
                                            }
                                        }
                                    }
                                }
                            }
                        });
                    }
                    
                    function createResultsTable(data) {
                        let tableHtml = `
                            <h3>Szczegółowe wyniki</h3>
                            <table class="results-table">
                                <thead>
                                    <tr>
                                        <th>System SIEM</th>
                                        <th>Wskaźnik wykrywalności</th>
                                        <th>Wykryte techniki</th>
                                        <th>Łączna liczba zdarzeń</th>
                                        <th>Status</th>
                                    </tr>
                                </thead>
                                <tbody>
                        `;
                        
                        for (const [siem, results] of Object.entries(data.siem_results)) {
                            const rate = results.detection_rate;
                            let badgeClass = 'detection-low';
                            let statusText = 'Niski';
                            
                            if (rate >= 70) {
                                badgeClass = 'detection-high';
                                statusText = 'Wysoki';
                            } else if (rate >= 40) {
                                badgeClass = 'detection-medium';
                                statusText = 'Średni';
                            }
                            
                            tableHtml += `
                                <tr>
                                    <td><strong>${siem.toUpperCase()}</strong></td>
                                    <td>${rate.toFixed(1)}%</td>
                                    <td>${results.techniques_detected.length} / ${data.techniques_used.length}</td>
                                    <td>${results.total_events}</td>
                                    <td><span class="detection-badge ${badgeClass}">${statusText}</span></td>
                                </tr>
                            `;
                        }
                        
                        tableHtml += `</tbody></table>`;
                        document.getElementById('resultsTable').innerHTML = tableHtml;
                    }
                    
                    async function checkSIEMStatus() {
                        const statusDisplay = document.getElementById('statusDisplay');
                        
                        try {
                            const response = await fetch('/plugin/detmeter/api/status');
                            const status = await response.json();
                            
                            let html = `
                                <div class="card">
                                    <h2>🔍 Status połączenia z systemami SIEM</h2>
                                    <div class="status-grid">
                            `;
                            
                            for (const [siem, info] of Object.entries(status)) {
                                const statusClass = info.status === 'reachable' ? 'status-up' : 'status-down';
                                const statusIcon = info.status === 'reachable' ? '✅' : '❌';
                                const enabledText = info.enabled ? 'Tak' : 'Nie';
                                
                                html += `
                                    <div class="status-card ${statusClass}">
                                        <h3 style="margin-top: 0;">${statusIcon} ${siem.toUpperCase()}</h3>
                                        <p><strong>Status:</strong> ${info.status === 'reachable' ? 'Dostępny' : 'Niedostępny'}</p>
                                        <p><strong>Włączony:</strong> ${enabledText}</p>
                                        <p><strong>Endpoint:</strong><br>
                                        <code style="font-size: 0.85em; word-break: break-all;">${info.endpoint || 'Nie skonfigurowano'}</code></p>
                                    </div>
                                `;
                            }
                            
                            html += `</div></div>`;
                            statusDisplay.innerHTML = html;
                            statusDisplay.style.display = 'block';
                            
                        } catch (error) {
                            statusDisplay.innerHTML = `
                                <div class="card" style="border-left-color: #e74c3c;">
                                    <h3>❌ Błąd sprawdzania statusu</h3>
                                    <p>${error.message}</p>
                                </div>
                            `;
                            statusDisplay.style.display = 'block';
                        }
                    }
                </script>
            </body>
            </html>
            """
            
            return web.Response(text=html_content, content_type='text/html')
            
        except Exception as e:
            self.log.error(f'Błąd przy serwowaniu UI: {e}')
            return web.Response(text=f'<h1>Błąd DetMeter</h1><p>{str(e)}</p>', content_type='text/html')
    
    async def serve_gui(self, request):
        """Backward compatibility - legacy GUI endpoint"""
        return await self.serve_ui_wrapper(request)
    
    async def serve_static(self, request):
        """Serve static files"""
        path = request.match_info['path']
        full_path = os.path.join(self.static_path, path)
        
        if os.path.exists(full_path):
            return web.FileResponse(full_path)
        return web.Response(status=404)
    
    async def analyze_operation(self, request):
        """API endpoint to analyze operation detection"""
        try:
            data = await request.json()
            operation_id = data.get('operation_id')
            
            if not operation_id:
                return web.json_response({'error': 'Brakuje operation_id'}, status=400)
            
            report = await self.svc.analyze_operation(operation_id)
            return web.json_response(report)
            
        except Exception as e:
            self.log.error(f'Błąd analizy: {e}')
            return web.json_response({'error': str(e)}, status=500)
    
    async def get_siem_status(self, request):
        """Get SIEM connection status"""
        try:
            status = await self.svc.get_siem_status()
            return web.json_response(status)
        except Exception as e:
            self.log.error(f'Błąd statusu SIEM: {e}')
            return web.json_response({'error': str(e)}, status=500)
    
    async def get_operations_list(self, request):
        """Get list of available operations"""
        try:
            # Get all operations from Caldera
            operations = await self.data_svc.locate('operations')
            
            # Format for display
            formatted_ops = []
            for op in operations:
                if hasattr(op, 'id') and op.id:
                    techniques = await self.svc._extract_techniques(op)
                    formatted_ops.append({
                        'id': op.id,
                        'name': getattr(op, 'name', 'Brak nazwy'),
                        'start': getattr(op, 'start', None),
                        'finish': getattr(op, 'finish', None),
                        'technique_count': len(techniques)
                    })
            
            return web.json_response(formatted_ops)
            
        except Exception as e:
            self.log.error(f'Błąd pobierania operacji: {e}')
            return web.json_response({'error': str(e)}, status=500)
