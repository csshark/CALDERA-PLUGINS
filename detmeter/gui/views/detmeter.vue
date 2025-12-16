<template>
  <div class="detmeter-plugin">
    <!-- Header -->
    <div class="plugin-header">
      <h1>
        <i class="fa fa-chart-line"></i>
        DetMeter - SIEM vs Blue Agent Analysis
      </h1>
      <p class="plugin-description">
        Compare Blue agent detection times with SIEM detection times in real-time
      </p>
    </div>

    <!-- Tabs Navigation -->
    <div class="tabs">
      <button 
        :class="['tab', { active: activeTab === 'config' }]" 
        @click="activeTab = 'config'"
      >
        <i class="fa fa-cog"></i> Configuration
      </button>
      <button 
        :class="['tab', { active: activeTab === 'detections' }]" 
        @click="activeTab = 'detections'"
      >
        <i class="fa fa-list"></i> Live Detections
      </button>
      <button 
        :class="['tab', { active: activeTab === 'analytics' }]" 
        @click="activeTab = 'analytics'"
      >
        <i class="fa fa-chart-bar"></i> Analytics
      </button>
    </div>

    <!-- Configuration Tab -->
    <div v-if="activeTab === 'config'" class="tab-content config-tab">
      <div class="config-card">
        <h2><i class="fa fa-server"></i> SIEM Connection</h2>
        
        <div class="form-group">
          <label for="siem-select">SIEM System</label>
          <select id="siem-select" v-model="config.selected_siem">
            <option value="">-- Select SIEM --</option>
            <option value="Splunk">Splunk</option>
            <option value="QRadar">IBM QRadar</option>
            <option value="Elastic">Elastic SIEM</option>
          </select>
        </div>

        <div class="form-group">
          <label for="api-endpoint">API Endpoint</label>
          <input 
            id="api-endpoint" 
            type="text" 
            v-model="config.api_endpoint"
            placeholder="https://your-siem.com:8089"
          />
        </div>

        <div class="form-group">
          <label for="api-key">API Key / Token</label>
          <input 
            id="api-key" 
            type="password" 
            v-model="config.api_key"
            placeholder="Enter your API token"
          />
        </div>

        <div class="form-group">
          <label>
            <input type="checkbox" v-model="config.verify_ssl" />
            Verify SSL certificates
          </label>
        </div>

        <div class="button-group">
          <button class="btn btn-primary" @click="testConnection">
            <i class="fa fa-plug"></i> Test Connection
          </button>
          <button class="btn btn-success" @click="saveConfig">
            <i class="fa fa-save"></i> Save Configuration
          </button>
          <button class="btn btn-info" @click="loadConfig">
            <i class="fa fa-sync"></i> Reload
          </button>
        </div>

        <div v-if="connectionTest.message" :class="['alert', connectionTest.status]">
          {{ connectionTest.message }}
        </div>

        <div class="demo-section">
          <h3><i class="fa fa-vial"></i> Demo Data</h3>
          <p>For testing without a real SIEM connection:</p>
          <div class="demo-buttons">
            <button class="btn btn-secondary" @click="addDemoBlue">
              <i class="fa fa-user-shield"></i> Add Demo Blue Detection
            </button>
            <button class="btn btn-secondary" @click="addDemoSiem">
              <i class="fa fa-shield-alt"></i> Add Demo SIEM Detection
            </button>
          </div>
        </div>
      </div>
    </div>

    <!-- Detections Tab -->
    <div v-if="activeTab === 'detections'" class="tab-content detections-tab">
      <div class="detections-card">
        <div class="detections-header">
          <h2><i class="fa fa-binoculars"></i> Live Detection Feed</h2>
          <div class="controls">
            <select v-model="selectedOperation" @change="loadDetections">
              <option value="">All Operations</option>
              <option v-for="op in operations" :value="op.id" :key="op.id">
                {{ op.name }} ({{ op.state }})
              </option>
            </select>
            <button class="btn btn-primary" @click="loadDetections">
              <i class="fa fa-sync"></i> Refresh
            </button>
            <button class="btn btn-danger" @click="clearData">
              <i class="fa fa-trash"></i> Clear
            </button>
            <button class="btn btn-info" @click="startAutoRefresh" v-if="!autoRefresh">
              <i class="fa fa-play"></i> Auto-refresh
            </button>
            <button class="btn btn-warning" @click="stopAutoRefresh" v-else>
              <i class="fa fa-stop"></i> Stop
            </button>
          </div>
        </div>

        <div v-if="loading" class="loading">
          <i class="fa fa-spinner fa-spin"></i> Loading detections...
        </div>

        <div v-else class="detections-list">
          <div class="detection-item header">
            <div class="type">Type</div>
            <div class="time">Time</div>
            <div class="details">Details</div>
            <div class="operation">Operation</div>
          </div>

          <div 
            v-for="detection in combinedDetections" 
            :key="detection.id"
            :class="['detection-item', detection.type]"
          >
            <div class="type">
              <span :class="['badge', detection.type]">
                <i :class="detection.type === 'blue' ? 'fa fa-user-shield' : 'fa fa-shield-alt'"></i>
                {{ detection.type === 'blue' ? 'Blue Agent' : 'SIEM' }}
              </span>
            </div>
            <div class="time">
              {{ formatTime(detection.timestamp) }}
            </div>
            <div class="details">
              <div v-if="detection.type === 'blue'">
                <strong>Command:</strong> {{ truncate(detection.command, 80) }}
                <div v-if="detection.agent" class="agent">
                  <small>Agent: {{ detection.agent }}</small>
                </div>
              </div>
              <div v-else>
                <strong>Rule:</strong> {{ detection.rule_id || 'Unknown' }}
                <div class="details-row">
                  <span class="severity" :class="detection.severity">
                    {{ detection.severity || 'medium' }}
                  </span>
                  <span class="confidence">
                    Confidence: {{ (detection.confidence * 100 || 0).toFixed(0) }}%
                  </span>
                </div>
              </div>
            </div>
            <div class="operation">
              Op {{ detection.operation_id || 'Unknown' }}
            </div>
          </div>

          <div v-if="combinedDetections.length === 0" class="no-data">
            <i class="fa fa-inbox"></i>
            <p>No detections found</p>
            <p class="hint">Run an operation or add demo data to see detections</p>
          </div>
        </div>
      </div>
    </div>

    <!-- Analytics Tab -->
    <div v-if="activeTab === 'analytics'" class="tab-content analytics-tab">
      <div class="analytics-card">
        <div class="analytics-header">
          <h2><i class="fa fa-chart-pie"></i> Detection Analytics</h2>
          <select v-model="selectedSummaryOperation" @change="loadSummary">
            <option value="">All Operations</option>
            <option v-for="op in operations" :value="op.id" :key="op.id">
              {{ op.name }} ({{ op.state }})
            </option>
          </select>
        </div>

        <div v-if="summaryLoading" class="loading">
          <i class="fa fa-spinner fa-spin"></i> Generating analytics...
        </div>

        <div v-else>
          <!-- Statistics Cards -->
          <div class="stats-grid">
            <div class="stat-card blue">
              <div class="stat-icon">
                <i class="fa fa-user-shield"></i>
              </div>
              <div class="stat-content">
                <div class="stat-value">{{ summary.total.blue || 0 }}</div>
                <div class="stat-label">Blue Detections</div>
              </div>
            </div>

            <div class="stat-card siem">
              <div class="stat-icon">
                <i class="fa fa-shield-alt"></i>
              </div>
              <div class="stat-content">
                <div class="stat-value">{{ summary.total.siem || 0 }}</div>
                <div class="stat-label">SIEM Detections</div>
              </div>
            </div>

            <div class="stat-card coverage">
              <div class="stat-icon">
                <i class="fa fa-percentage"></i>
              </div>
              <div class="stat-content">
                <div class="stat-value">{{ (summary.total.coverage || 0).toFixed(1) }}%</div>
                <div class="stat-label">Detection Coverage</div>
              </div>
            </div>
          </div>

          <!-- Timeline Chart -->
          <div class="chart-section">
            <h3><i class="fa fa-timeline"></i> Detection Timeline</h3>
            <div class="chart-container">
              <canvas ref="timelineChart"></canvas>
            </div>
          </div>

          <!-- Operation Details -->
          <div class="operation-stats" v-if="Object.keys(summary.by_operation).length > 0">
            <h3><i class="fa fa-table"></i> Operation Details</h3>
            <div class="operation-grid">
              <div 
                v-for="(stats, opId) in summary.by_operation" 
                :key="opId"
                class="operation-card"
              >
                <div class="operation-header">
                  <h4>Operation {{ opId }}</h4>
                  <span class="coverage-badge" :class="getCoverageClass(stats.coverage)">
                    {{ stats.coverage.toFixed(1) }}% coverage
                  </span>
                </div>
                <div class="operation-stats-grid">
                  <div class="stat">
                    <div class="stat-value">{{ stats.blue_count }}</div>
                    <div class="stat-label">Blue</div>
                  </div>
                  <div class="stat">
                    <div class="stat-value">{{ stats.siem_count }}</div>
                    <div class="stat-label">SIEM</div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script>

export default {
  name: 'DetMeter',
  
  data() {
    return {
      activeTab: 'config',
      config: {
        selected_siem: '',
        api_endpoint: '',
        api_key: '',
        verify_ssl: true
      },
      connectionTest: {
        status: '',
        message: ''
      },
      detections: {
        blue: [],
        siem: []
      },
      operations: [],
      selectedOperation: '',
      selectedSummaryOperation: '',
      summary: {
        total: { blue: 0, siem: 0, coverage: 0 },
        by_operation: {},
        timeline: []
      },
      loading: false,
      summaryLoading: false,
      autoRefresh: false,
      refreshInterval: null,
      chartInstance: null
    };
  },
  
  computed: {
    combinedDetections() {
      const blue = this.detections.blue.map(d => ({ ...d, type: 'blue' }));
      const siem = this.detections.siem.map(d => ({ ...d, type: 'siem' }));
      return [...blue, ...siem]
        .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
    }
  },
  
  async mounted() {
    await this.loadConfig();
    await this.loadOperations();
    this.loadDetections();
    this.loadSummary();
  },
  
  beforeDestroy() {
    this.stopAutoRefresh();
    if (this.chartInstance) {
      this.chartInstance.destroy();
    }
  },
  
  methods: {
    async loadConfig() {
      try {
        const response = await fetch('/plugin/detmeter/config');
        this.config = await response.json();
      } catch (error) {
        console.error('Error loading config:', error);
        this.showAlert('Error loading configuration', 'error');
      }
    },
    
    async saveConfig() {
      try {
        const response = await fetch('/plugin/detmeter/config', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(this.config)
        });
        
        if (response.ok) {
          this.showAlert('Configuration saved successfully', 'success');
        } else {
          this.showAlert('Error saving configuration', 'error');
        }
      } catch (error) {
        console.error('Error saving config:', error);
        this.showAlert('Error saving configuration', 'error');
      }
    },
    
    async testConnection() {
      if (!this.config.selected_siem) {
        this.showAlert('Please select a SIEM system', 'error');
        return;
      }
      
      this.connectionTest = { status: 'info', message: 'Testing connection...' };
      
      try {
        const response = await fetch('/plugin/detmeter/test', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(this.config)
        });
        
        const result = await response.json();
        this.connectionTest = result;
        
        if (result.status === 'success') {
          this.showAlert(result.message, 'success');
        } else {
          this.showAlert(result.message, 'error');
        }
      } catch (error) {
        this.connectionTest = { status: 'error', message: 'Connection test failed' };
        this.showAlert('Connection test failed', 'error');
      }
    },
    
    async loadOperations() {
      try {
        const response = await fetch('/plugin/detmeter/operations');
        this.operations = await response.json();
      } catch (error) {
        console.error('Error loading operations:', error);
      }
    },
    
    async loadDetections() {
      this.loading = true;
      try {
        let url = '/plugin/detmeter/data';
        if (this.selectedOperation) {
          url += `?operation_id=${this.selectedOperation}`;
        }
        
        const response = await fetch(url);
        this.detections = await response.json();
      } catch (error) {
        console.error('Error loading detections:', error);
        this.showAlert('Error loading detections', 'error');
      } finally {
        this.loading = false;
      }
    },
    
    async loadSummary() {
      this.summaryLoading = true;
      try {
        let url = '/plugin/detmeter/summary';
        if (this.selectedSummaryOperation) {
          url += `?operation_id=${this.selectedSummaryOperation}`;
        }
        
        const response = await fetch(url);
        this.summary = await response.json();
        this.renderChart();
      } catch (error) {
        console.error('Error loading summary:', error);
        this.showAlert('Error loading analytics', 'error');
      } finally {
        this.summaryLoading = false;
      }
    },
    
    async clearData() {
      if (!confirm('Are you sure you want to clear all detection data?')) {
        return;
      }
      
      try {
        const response = await fetch('/plugin/detmeter/clear', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ operation_id: this.selectedOperation || null })
        });
        
        if (response.ok) {
          this.loadDetections();
          this.loadSummary();
          this.showAlert('Data cleared successfully', 'success');
        }
      } catch (error) {
        this.showAlert('Error clearing data', 'error');
      }
    },
    
    async addDemoBlue() {
      try {
        const response = await fetch('/plugin/detmeter/demo/blue', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ 
            operation_id: 'demo',
            command: 'whoami && hostname && ipconfig'
          })
        });
        
        if (response.ok) {
          this.loadDetections();
          this.loadSummary();
          this.showAlert('Demo blue detection added', 'success');
        }
      } catch (error) {
        this.showAlert('Error adding demo detection', 'error');
      }
    },
    
    async addDemoSiem() {
      try {
        const response = await fetch('/plugin/detmeter/demo/siem', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ 
            operation_id: 'demo',
            rule_id: 'DEMO_RULE_' + Math.floor(Math.random() * 1000)
          })
        });
        
        if (response.ok) {
          this.loadDetections();
          this.loadSummary();
          this.showAlert('Demo SIEM detection added', 'success');
        }
      } catch (error) {
        this.showAlert('Error adding demo detection', 'error');
      }
    },
    
    startAutoRefresh() {
      this.autoRefresh = true;
      this.refreshInterval = setInterval(() => {
        this.loadDetections();
      }, 5000); // Refresh every 5 seconds
    },
    
    stopAutoRefresh() {
      this.autoRefresh = false;
      if (this.refreshInterval) {
        clearInterval(this.refreshInterval);
        this.refreshInterval = null;
      }
    },
    
    renderChart() {
      if (this.chartInstance) {
        this.chartInstance.destroy();
      }
      
      const ctx = this.$refs.timelineChart.getContext('2d');
      
      // Prepare data for chart
      const bluePoints = this.combinedDetections
  .filter(d => d.type === 'blue')
  .map((d, i) => ({
    x: new Date(d.timestamp).getTime(),
    y: i,
    label: `Blue: ${d.command.substring(0, 30)}...`
  }));

const siemPoints = this.combinedDetections
  .filter(d => d.type === 'siem')
  .map((d, i) => ({
    x: new Date(d.timestamp).getTime(),
    y: i + bluePoints.length,
    label: `SIEM: ${d.rule_id || 'Unknown'}`
  }));      
      this.chartInstance = new Chart(ctx, {
        type: 'scatter',
        data: {
          datasets: [
            {
              label: 'Blue Agent',
              data: bluePoints,
              backgroundColor: 'rgba(52, 152, 219, 0.7)',
              borderColor: 'rgba(52, 152, 219, 1)',
              pointRadius: 6,
              pointHoverRadius: 8
            },
            {
              label: 'SIEM',
              data: siemPoints,
              backgroundColor: 'rgba(155, 89, 182, 0.7)',
              borderColor: 'rgba(155, 89, 182, 1)',
              pointRadius: 6,
              pointHoverRadius: 8
            }
          ]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            title: {
              display: true,
              text: 'Detection Timeline'
            },
            tooltip: {
              callbacks: {
                label: function(context) {
                  return context.raw.label;
                }
              }
            }
          },
          scales: {
            x: {
  type: 'linear',
  ticks: {
    callback: (value) => {
      const date = new Date(value);
      return date.toLocaleTimeString([], {
        hour: '2-digit',
        minute: '2-digit'
      });
    }
  },
  title: {
    display: true,
    text: 'Time'
  }
},            y: {
              display: false
            }
          }
        }
      });
    },
    
    formatTime(timestamp) {
      if (!timestamp) return 'Unknown';
      const date = new Date(timestamp);
      return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    },
    
    truncate(text, length) {
      if (text.length <= length) return text;
      return text.substring(0, length) + '...';
    },
    
    getCoverageClass(coverage) {
      if (coverage >= 80) return 'good';
      if (coverage >= 50) return 'medium';
      return 'poor';
    },
    
    showAlert(message, type) {
      // Implement alert system or use console
      console.log(`${type}: ${message}`);
    }
  }
};
</script>

<style scoped>
.detmeter-plugin {
  padding: 20px;
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
}

.plugin-header {
  background: linear-gradient(135deg, #2c3e50, #3498db);
  color: black;
  padding: 25px;
  border-radius: 10px;
  margin-bottom: 20px;
  box-shadow: 0 4px 6px rgba(0,0,0,0.1);
}

.plugin-header h1 {
  margin: 0;
  font-size: 28px;
  display: flex;
  align-items: center;
  gap: 10px;
}

.plugin-description {
  margin: 10px 0 0 0;
  opacity: 0.9;
  font-size: 16px;
}

.tabs {
  display: flex;
  background: black;
  border-radius: 8px;
  margin-bottom: 20px;
  box-shadow: 0 2px 4px rgba(0,0,0,0.1);
}

.tab {
  flex: 1;
  padding: 15px 20px;
  border: none;
  background: none;
  font-size: 16px;
  font-weight: 600;
  color: #6c757d;
  cursor: pointer;
  transition: all 0.3s;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
}

.tab:hover {
  background: #f8f9fa;
  color: #3498db;
}

.tab.active {
  color: #3498db;
  border-bottom: 3px solid #3498db;
  background: #f8f9fa;
}

.tab-content {
  animation: fadeIn 0.3s ease;
}

@keyframes fadeIn {
  from { opacity: 0; }
  to { opacity: 1; }
}

.config-card,
.detections-card,
.analytics-card {
  background: black;
  border-radius: 10px;
  padding: 25px;
  box-shadow: 0 4px 6px rgba(0,0,0,0.1);
}

.form-group {
  margin-bottom: 20px;
}

.form-group label {
  display: block;
  margin-bottom: 8px;
  font-weight: 600;
  color: #2c3e50;
}

.form-group input,
.form-group select {
  width: 100%;
  padding: 12px;
  border: 2px solid #434445;
  border-radius: 6px;
  font-size: 14px;
  transition: border-color 0.3s;
}

.form-group input:focus,
.form-group select:focus {
  outline: none;
  border-color: #3498db;
  box-shadow: 0 0 0 3px rgba(52, 152, 219, 0.1);
}

.button-group {
  display: flex;
  gap: 10px;
  margin-top: 25px;
}

.btn {
  padding: 12px 24px;
  border: none;
  border-radius: 6px;
  font-size: 14px;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.3s;
  display: flex;
  align-items: center;
  gap: 8px;
}

.btn-primary {
  background: #3498db;
  color: black;
}

.btn-primary:hover {
  background: #2980b9;
}

.btn-success {
  background: #27ae60;
  color: purple;
}

.btn-success:hover {
  background: #219653;
}

.btn-info {
  background: #17a2b8;
  color: black;
}

.btn-info:hover {
  background: #138496;
}

.btn-danger {
  background: #e74c3c;
  color: black;
}

.btn-danger:hover {
  background: #c0392b;
}

.btn-warning {
  background: #f39c12;
  color: black;
}

.btn-warning:hover {
  background: #d68910;
}

.btn-secondary {
  background: #6c757d;
  color: black;
}

.btn-secondary:hover {
  background: #5a6268;
}

.alert {
  padding: 15px;
  border-radius: 6px;
  margin-top: 20px;
  font-weight: 500;
}

.alert.success {
  background: #d5f4e6;
  color: #27ae60;
  border: 1px solid #a3e9c4;
}

.alert.error {
  background: #fadbd8;
  color: #e74c3c;
  border: 1px solid #f5b7b1;
}

.alert.info {
  background: #d6eaf8;
  color: #3498db;
  border: 1px solid #aed6f1;
}

.demo-section {
  margin-top: 30px;
  padding-top: 20px;
  border-top: 2px solid #dee2e6;
}

.demo-section h3 {
  margin-bottom: 15px;
  color: #2c3e50;
}

.demo-buttons {
  display: flex;
  gap: 10px;
  flex-wrap: wrap;
}

.detections-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 25px;
  flex-wrap: wrap;
  gap: 15px;
}

.detections-header h2 {
  margin: 0;
  color: #2c3e50;
}

.controls {
  display: flex;
  gap: 10px;
  align-items: center;
}

.controls select {
  padding: 10px;
  border: 2px solid #414345;
  border-radius: 6px;
  font-size: 14px;
  min-width: 200px;
}

.loading {
  text-align: center;
  padding: 40px;
  color: #6c757d;
  font-size: 16px;
}

.detections-list {
  border: 2px solid #414345;
  border-radius: 8px;
  overflow: hidden;
}

.detection-item {
  display: grid;
  grid-template-columns: 120px 150px 1fr 100px;
  gap: 15px;
  padding: 15px;
  border-bottom: 1px solid #414345;
  align-items: center;
}

.detection-item.header {
  background: #414345;
  font-weight: 600;
  color: #2c3e50;
}

.detection-item:last-child {
  border-bottom: none;
}

.detection-item.blue {
  background: #414345;
}

.detection-item.siem {
  background: #414345;
}

.badge {
  padding: 6px 12px;
  border-radius: 20px;
  font-size: 12px;
  font-weight: 600;
  display: inline-flex;
  align-items: center;
  gap: 5px;
}

.badge.blue {
  background: #d6eaf8;
  color: #21618c;
}

.badge.siem {
  background: #e8daef;
  color: #6c3483;
}

.details-row {
  display: flex;
  gap: 10px;
  margin-top: 5px;
  align-items: center;
}

.severity {
  padding: 4px 8px;
  border-radius: 4px;
  font-size: 11px;
  font-weight: 600;
  text-transform: uppercase;
}

.severity.high {
  background: #fadbd8;
  color: #c0392b;
}

.severity.medium {
  background: #fcf3cf;
  color: #b7950b;
}

.severity.low {
  background: #d5f4e6;
  color: #27ae60;
}

.confidence {
  font-size: 12px;
  color: #6c757d;
}

.no-data {
  text-align: center;
  padding: 50px;
  color: #6c757d;
}

.no-data i {
  font-size: 48px;
  margin-bottom: 15px;
  opacity: 0.5;
}

.no-data .hint {
  font-size: 14px;
  margin-top: 10px;
  opacity: 0.7;
}

.stats-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
  gap: 20px;
  margin-bottom: 30px;
}

.stat-card {
  background: black;
  border-radius: 10px;
  padding: 25px;
  display: flex;
  align-items: center;
  gap: 20px;
  box-shadow: 0 4px 6px rgba(0,0,0,0.1);
  transition: transform 0.3s;
}

.stat-card:hover {
  transform: translateY(-5px);
}

.stat-card.blue {
  border-left: 5px solid #3498db;
}

.stat-card.siem {
  border-left: 5px solid #9b59b6;
}

.stat-card.coverage {
  border-left: 5px solid #27ae60;
}

.stat-icon {
  font-size: 40px;
  color: #2c3e50;
}

.stat-content {
  flex: 1;
}

.stat-value {
  font-size: 32px;
  font-weight: bold;
  margin-bottom: 5px;
}

.stat-card.blue .stat-value {
  color: #3498db;
}

.stat-card.siem .stat-value {
  color: #9b59b6;
}

.stat-card.coverage .stat-value {
  color: #27ae60;
}

.stat-label {
  color: #6c757d;
  font-size: 14px;
}

.chart-section {
  margin-top: 30px;
  padding: 25px;
  background: black;
  border-radius: 10px;
  box-shadow: 0 4px 6px rgba(0,0,0,0.1);
}

.chart-container {
  height: 400px;
  margin-top: 20px;
  position: relative;
}

.operation-stats {
  margin-top: 30px;
}

.operation-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
  gap: 20px;
  margin-top: 20px;
}

.operation-card {
  background: black;
  border-radius: 10px;
  padding: 20px;
  box-shadow: 0 4px 6px rgba(0,0,0,0.1);
}

.operation-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 15px;
}

.operation-header h4 {
  margin: 0;
  color: #2c3e50;
}

.coverage-badge {
  padding: 6px 12px;
  border-radius: 20px;
  font-size: 12px;
  font-weight: 600;
}

.coverage-badge.good {
  background: #d5f4e6;
  color: #27ae60;
}

.coverage-badge.medium {
  background: #fcf3cf;
  color: #b7950b;
}

.coverage-badge.poor {
  background: #fadbd8;
  color: #c0392b;
}

.operation-stats-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 15px;
}

.operation-stats-grid .stat {
  text-align: center;
  padding: 15px;
  background: #f8f9fa;
  border-radius: 8px;
}

.operation-stats-grid .stat-value {
  font-size: 24px;
  font-weight: bold;
  margin-bottom: 5px;
}

.operation-stats-grid .stat-label {
  font-size: 14px;
  color: #6c757d;
}

@media (max-width: 768px) {
  .detection-item {
    grid-template-columns: 1fr;
    gap: 10px;
  }
  
  .detections-header {
    flex-direction: column;
    align-items: stretch;
  }
  
  .controls {
    flex-wrap: wrap;
  }
  
  .stats-grid {
    grid-template-columns: 1fr;
  }
  
  .operation-grid {
    grid-template-columns: 1fr;
  }
}
</style>
