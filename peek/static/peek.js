class BrowserDashboard {
    constructor() {
        this.history = [];
        this.currentIndex = -1;
        this.currentUrl = 'https://www.google.com';
        this.iframe = document.getElementById('browser-frame');
        this.urlDisplay = document.getElementById('current-url');
        this.opName = document.getElementById('op-name');
        this.opState = document.getElementById('op-state');
        this.opStart = document.getElementById('op-start');
        this.opAgents = document.getElementById('op-agents');
        
        this.init();
    }

    init() {
        this.loadOperationStatus();
        setInterval(() => this.loadOperationStatus(), 30000);
        
        this.iframe.onload = () => {
            this.urlDisplay.textContent = this.iframe.src;
        };
    }

    async navigateTo(target) {
        try {
            const response = await fetch('/plugin/peek/navigate', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({target: target})
            });
            
            const data = await response.json();
            
            this.history.push(this.currentUrl);
            this.currentIndex = this.history.length - 1;
            this.currentUrl = data.url;
            
            this.iframe.src = data.url;
            this.urlDisplay.textContent = data.url;
            
        } catch (error) {
            console.error('Navigation error:', error);
        }
    }

    goBack() {
        if (this.currentIndex > 0) {
            this.currentIndex--;
            const previousUrl = this.history[this.currentIndex];
            
            this.iframe.src = previousUrl;
            this.currentUrl = previousUrl;
            this.urlDisplay.textContent = previousUrl;
        }
    }

    async loadOperationStatus() {
        try {
            const response = await fetch('/plugin/browser/current_operation');
            const data = await response.json();
            
            this.opName.textContent = data.name;
            this.opState.textContent = data.state;
            this.opState.className = `value ${data.state}`;
            this.opStart.textContent = data.start || '-';
            this.opAgents.textContent = data.agents || 0;
            
        } catch (error) {
            console.error('Failed to load operation status:', error);
        }
    }
}

document.addEventListener('DOMContentLoaded', () => {
    window.browserDashboard = new BrowserDashboard();
    
    document.querySelectorAll('.nav-btn').forEach(btn => {
        btn.addEventListener('click', function(e) {
            this.style.transform = 'scale(0.98)';
            setTimeout(() => {
                this.style.transform = '';
            }, 150);
        });
    });
});
