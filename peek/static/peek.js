class PeekBrowser {
    constructor() {
        this.history = [];
        this.currentIndex = -1;
        this.currentUrl = '';
        this.urls = {};
        this.iframe = document.getElementById('peek-frame');
        this.opName = document.getElementById('op-name');
        this.opState = document.getElementById('op-state');
        this.opStart = document.getElementById('op-start');
        this.opAgents = document.getElementById('op-agents');
        
        this.init();
    }

    async init() {
        await this.loadUrls();
        this.loadOperationStatus();
        setInterval(() => this.loadOperationStatus(), 5000);
        
        if (this.urls.home) {
            this.navigateTo('home');
        }
    }

    async loadUrls() {
        try {
            const response = await fetch('/plugin/peek/urls');
            this.urls = await response.json();
        } catch (error) {
            console.error('Failed to load URLs:', error);
            this.urls = {};
        }
    }

    navigateTo(target) {
        if (this.urls[target]) {
            if (this.currentUrl) {
                this.history.push(this.currentUrl);
                this.currentIndex = this.history.length - 1;
            }
            this.currentUrl = this.urls[target];
            this.iframe.src = this.urls[target];
        }
    }

    goBack() {
        if (this.currentIndex > 0) {
            this.currentIndex--;
            this.currentUrl = this.history[this.currentIndex];
            this.iframe.src = this.currentUrl;
        }
    }

    async loadOperationStatus() {
        try {
            const response = await fetch('/plugin/peek/operation');
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
    window.peek = new PeekBrowser();
});
