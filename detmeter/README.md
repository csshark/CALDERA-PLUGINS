# DeTmeter

<p align="center">
  <img src="/detmeter/logo.png" alt="DeTmeter logo" width="500" height="500">
</p>


<body>
    <div class="section">
        <h2> Overview</h2>
        <p>DetMeter validates SIEM detection capabilities by comparing executed ATT&CK techniques with actual SIEM detections, providing measurable security control effectiveness.</p>
    </div>
    <div class="section">
        <h2> Features</h2>
        <div class="feature-grid">
            <div class="feature-card">
                <h3>Detection Gap Analysis</h3>
                <p>Identifies which ATT&CK techniques went undetected by your SIEM</p>
            </div>
            <div class="feature-card">
                <h3>Multi-SIEM Support</h3>
                <p>Compatible with ArcSight, Splunk, QRadar,Elastic and more!</p>
            </div>
            <div class="feature-card">
                <h3>Real-time Validation</h3>
                <p>Automatically validates detections post-operation</p>
            </div>
            <div class="feature-card">
                <h3>Metrics Dashboard</h3>
                <p>Visual detection rate reporting and analytics</p>
            </div>
        </div>
    </div>
    <div class="section">
        <h2>Installation</h2>
        <p>1. Copy to Caldera plugins directory:
        <code>cp -r detmeter /path/to/caldera/plugins/</code></div>
        <p>2. Configure SIEM connection in Caldera's main config:</p>
      <pre><code>plugins:
  - compass
  - sandcat 
  - ssl
  - detmeter #enable me ! 
  - atomic 
  - fieldmanual</code></pre>
        <p>3. Restart Caldera service</p>
    </div>
    <div class="section">
        <h2>Usage</h2>  
        <h3>Web Interface</h3>
        <p>Access via: <code>http://caldera-server:8888/plugins/detmeter/gui</code></p>        
        <h3>API Endpoints</h3>
        <ul>
            <li><code>POST /plugin/detmeter/validate/{operation_id}</code> - Validate detection for operation</li>
            <li><code>GET /plugin/detmeter/results/{operation_id}</code> - Get validation results</li>
        </ul>  
        <h3>Example API Call</h3>
        <div class="code">
curl -X POST http://localhost:8888/plugin/detmeter/validate/OP123456
        </div> 
        <h3>Sample Response</h3>
        <pre><code>
{
  "operation_id": "OP123456",
  "operation_name": "Red Team Exercise",
  "techniques_used": ["T1055", "T1078", "T1566"],
  "techniques_detected": ["T1055", "T1566"],
  "detection_rate": 66.7,
  "siem_events_count": 42
}
        </code></pre>
    </div>
    <div class="section">
        <h2>Configuration</h2>   
        <h3>Supported SIEM Systems</h3>
        <ul>
            <li><strong>ArcSight</strong>: REST API with bearer token</li>
            <li><strong>Splunk</strong>: Search API integration</li>
            <li><strong>QRadar</strong>: Ariel API queries</li>
            <li><strong>Elastic</strong>: Elasticsearch queries</li>
            <li>...and so goes on with other.</li>
        </ul>     
        <h3>Flexible Parameters</h3>
        <table class="config-table">
            <tr>
                <th>Parameter</th>
                <th>Description</th>
                <th>Default</th>
            </tr>
            <tr>
                <td>siem.type</td>
                <td>SIEM vendor (arcsight/splunk/qradar/elastic)</td>
                <td>arcsight</td>
            </tr>
            <tr>
                <td>api_endpoint</td>
                <td>SIEM API base URL</td>
                <td>https://localhost:8443</td>
            </tr>
            <tr>
                <td>api_token</td>
                <td>Authentication token</td>
                <td>default_token</td>
            </tr>
            <tr>
                <td>verify_ssl</td>
                <td>SSL certificate validation</td>
                <td>false</td>
            </tr>
        </table>
    </div>
    <div class="section">
        <h2>Architecture</h2>
        <pre><code>
detmeter/
├── app/detmeter_api.py     # Core validation logic
├── gui/views.py           # Web interface handlers  
├── static/css/            # Styling assets
├── templates/             # HTML templates
└── payloads/              # Extension payloads
        </code></pre>
    </div>
    <div class="section">
        <h2>Requirements</h2>
        <ul>
            <li>MITRE Caldera 5.0+</li>
            <li>SIEM with REST API access</li>
            <li>Network connectivity between Caldera and SIEM</li>
        </ul>
    </div>
    <div class="section">
        <h2>Development</h2>
        <p>The plugin uses Caldera's standard plugin architecture with BaseService for core functionality, aiohttp for web endpoints, and configurable SIEM connectors.</p>
    </div>
    <div class="section">
        <h2>License</h2>
        <p>Same as MITRE Caldera - Apache 2.0</p>
    </div>
</body>
</html>
