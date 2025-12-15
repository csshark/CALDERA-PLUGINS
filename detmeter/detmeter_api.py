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
                        <div id="techniques-tab" class="
