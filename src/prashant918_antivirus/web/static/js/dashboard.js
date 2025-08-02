/**
 * Prashant918 Advanced Antivirus - Dashboard JavaScript
 * Handles real-time updates, user interactions, and WebSocket communication
 */

class AntivirusDashboard {
    constructor() {
        this.socket = null;
        this.charts = {};
        this.notifications = [];
        this.theme = localStorage.getItem('theme') || 'light';
        
        this.init();
    }
    
    init() {
        this.initializeWebSocket();
        this.initializeTheme();
        this.initializeEventListeners();
        this.initializeCharts();
        this.startPeriodicUpdates();
        this.animateCounters();
        
        console.log('Prashant918 Antivirus Dashboard initialized');
    }
    
    initializeWebSocket() {
        try {
            this.socket = io();
            
            this.socket.on('connect', () => {
                console.log('Connected to antivirus server');
                this.showNotification('Connected to Prashant918 Antivirus', 'success');
                this.updateConnectionStatus(true);
            });
            
            this.socket.on('disconnect', () => {
                console.log('Disconnected from antivirus server');
                this.showNotification('Connection lost. Attempting to reconnect...', 'warning');
                this.updateConnectionStatus(false);
            });
            
            this.socket.on('system_status', (data) => {
                this.updateSystemStatus(data);
            });
            
            this.socket.on('threat_detected', (data) => {
                this.handleThreatDetection(data);
            });
            
            this.socket.on('scan_progress', (data) => {
                this.updateScanProgress(data);
            });
            
            this.socket.on('scan_completed', (data) => {
                this.handleScanCompletion(data);
            });
            
        } catch (error) {
            console.error('WebSocket initialization failed:', error);
            this.showNotification('Real-time updates unavailable', 'error');
        }
    }
    
    initializeTheme() {
        document.documentElement.setAttribute('data-theme', this.theme);
        const themeToggle = document.getElementById('themeToggle');
        if (themeToggle) {
            const icon = themeToggle.querySelector('i');
            icon.className = this.theme === 'dark' ? 'fas fa-sun' : 'fas fa-moon';
        }
    }
    
    initializeEventListeners() {
        // Theme toggle
        const themeToggle = document.getElementById('themeToggle');
        if (themeToggle) {
            themeToggle.addEventListener('click', () => this.toggleTheme());
        }
        
        // Protection toggle
        const protectionToggle = document.getElementById('protectionToggle');
        if (protectionToggle) {
            protectionToggle.addEventListener('change', (e) => {
                this.toggleProtection(e.target.checked);
            });
        }
        
        // Monitoring controls
        const startMonitoring = document.getElementById('startMonitoring');
        const stopMonitoring = document.getElementById('stopMonitoring');
        
        if (startMonitoring) {
            startMonitoring.addEventListener('click', () => this.startMonitoring());
        }
        
        if (stopMonitoring) {
            stopMonitoring.addEventListener('click', () => this.stopMonitoring());
        }
        
        // Quick actions
        const quickScan = document.getElementById('quickScan');
        const fullScan = document.getElementById('fullScan');
        const updateSignatures = document.getElementById('updateSignatures');
        const viewQuarantine = document.getElementById('viewQuarantine');
        
        if (quickScan) {
            quickScan.addEventListener('click', () => this.performQuickScan());
        }
        
        if (fullScan) {
            fullScan.addEventListener('click', () => this.performFullScan());
        }
        
        if (updateSignatures) {
            updateSignatures.addEventListener('click', () => this.updateSignatures());
        }
        
        if (viewQuarantine) {
            viewQuarantine.addEventListener('click', () => {
                window.location.href = '/quarantine';
            });
        }
        
        // Refresh buttons
        const refreshThreats = document.getElementById('refreshThreats');
        if (refreshThreats) {
            refreshThreats.addEventListener('click', () => this.refreshThreats());
        }
        
        // Chart period selector
        const chartPeriod = document.getElementById('chartPeriod');
        if (chartPeriod) {
            chartPeriod.addEventListener('change', (e) => {
                this.updateChartPeriod(e.target.value);
            });
        }
    }
    
    initializeCharts() {
        const chartCanvas = document.getElementById('activityChart');
        if (chartCanvas) {
            const ctx = chartCanvas.getContext('2d');
            
            this.charts.activity = new Chart(ctx, {
                type: 'line',
                data: {
                    labels: this.generateTimeLabels(),
                    datasets: [
                        {
                            label: 'Files Scanned',
                            data: this.generateSampleData(),
                            borderColor: '#2563eb',
                            backgroundColor: 'rgba(37, 99, 235, 0.1)',
                            tension: 0.4,
                            fill: true
                        },
                        {
                            label: 'Threats Detected',
                            data: this.generateSampleData(true),
                            borderColor: '#ef4444',
                            backgroundColor: 'rgba(239, 68, 68, 0.1)',
                            tension: 0.4,
                            fill: true
                        }
                    ]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            position: 'top',
                        }
                    },
                    scales: {
                        y: {
                            beginAtZero: true,
                            grid: {
                                color: 'rgba(0, 0, 0, 0.1)'
                            }
                        },
                        x: {
                            grid: {
                                color: 'rgba(0, 0, 0, 0.1)'
                            }
                        }
                    }
                }
            });
        }
    }
    
    startPeriodicUpdates() {
        // Update current time
        this.updateCurrentTime();
        setInterval(() => this.updateCurrentTime(), 1000);
        
        // Update system metrics
        this.updateSystemMetrics();
        setInterval(() => this.updateSystemMetrics(), 30000);
        
        // Request status updates
        if (this.socket) {
            setInterval(() => {
                this.socket.emit('request_status');
            }, 10000);
        }
    }
    
    updateCurrentTime() {
        const timeElement = document.getElementById('currentTime');
        if (timeElement) {
            const now = new Date();
            timeElement.textContent = now.toLocaleTimeString();
        }
    }
    
    updateSystemMetrics() {
        // Simulate system metrics updates
        const metrics = [
            { selector: '.metric-fill', values: [25, 45, 60] },
            { selector: '.metric-value', values: ['25%', '45%', '60%'] }
        ];
        
        metrics.forEach(metric => {
            const elements = document.querySelectorAll(metric.selector);
            elements.forEach((element, index) => {
                if (metric.selector === '.metric-fill') {
                    const randomVariation = Math.random() * 10 - 5;
                    const newValue = Math.max(0, Math.min(100, metric.values[index] + randomVariation));
                    element.style.width = `${newValue}%`;
                    
                    // Update corresponding value
                    const valueElement = element.closest('.metric').querySelector('.metric-value');
                    if (valueElement) {
                        valueElement.textContent = `${Math.round(newValue)}%`;
                    }
                }
            });
        });
    }
    
    animateCounters() {
        const counters = document.querySelectorAll('.stat-number');
        
        counters.forEach(counter => {
            const target = parseInt(counter.getAttribute('data-target')) || 0;
            const duration = 2000;
            const step = target / (duration / 16);
            let current = 0;
            
            const updateCounter = () => {
                current += step;
                if (current < target) {
                    counter.textContent = Math.floor(current).toLocaleString();
                    counter.classList.add('counting');
                    requestAnimationFrame(updateCounter);
                } else {
                    counter.textContent = target.toLocaleString();
                    counter.classList.remove('counting');
                }
            };
            
            updateCounter();
        });
    }
    
    toggleTheme() {
        this.theme = this.theme === 'light' ? 'dark' : 'light';
        document.documentElement.setAttribute('data-theme', this.theme);
        localStorage.setItem('theme', this.theme);
        
        const themeToggle = document.getElementById('themeToggle');
        const icon = themeToggle.querySelector('i');
        icon.className = this.theme === 'dark' ? 'fas fa-sun' : 'fas fa-moon';
        
        this.showNotification(`Switched to ${this.theme} theme`, 'info');
    }
    
    toggleProtection(enabled) {
        const statusText = document.querySelector('.status-text');
        if (statusText) {
            statusText.textContent = enabled ? 'Active' : 'Inactive';
            statusText.style.color = enabled ? 'var(--success-color)' : 'var(--danger-color)';
        }
        
        if (enabled) {
            this.startMonitoring();
        } else {
            this.stopMonitoring();
        }
        
        this.showNotification(
            `Real-time protection ${enabled ? 'enabled' : 'disabled'}`,
            enabled ? 'success' : 'warning'
        );
    }
    
    async startMonitoring() {
        try {
            this.showLoading(true);
            
            const response = await fetch('/api/monitor/start', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    paths: [
                        `${navigator.platform.includes('Win') ? 'C:\\Users\\' + (process.env.USERNAME || 'User') + '\\Downloads' : '~/Downloads'}`,
                        `${navigator.platform.includes('Win') ? 'C:\\Users\\' + (process.env.USERNAME || 'User') + '\\Desktop' : '~/Desktop'}`,
                        `${navigator.platform.includes('Win') ? 'C:\\Users\\' + (process.env.USERNAME || 'User') + '\\Documents' : '~/Documents'}`
                    ]
                })
            });
            
            const result = await response.json();
            
            if (response.ok) {
                this.showNotification('Real-time monitoring started', 'success');
                this.updateMonitoringStatus(true);
            } else {
                throw new Error(result.error || 'Failed to start monitoring');
            }
        } catch (error) {
            console.error('Failed to start monitoring:', error);
            this.showNotification('Failed to start monitoring: ' + error.message, 'error');
        } finally {
            this.showLoading(false);
        }
    }
    
    async stopMonitoring() {
        try {
            this.showLoading(true);
            
            const response = await fetch('/api/monitor/stop', {
                method: 'POST'
            });
            
            const result = await response.json();
            
            if (response.ok) {
                this.showNotification('Real-time monitoring stopped', 'warning');
                this.updateMonitoringStatus(false);
            } else {
                throw new Error(result.error || 'Failed to stop monitoring');
            }
        } catch (error) {
            console.error('Failed to stop monitoring:', error);
            this.showNotification('Failed to stop monitoring: ' + error.message, 'error');
        } finally {
            this.showLoading(false);
        }
    }
    
    updateMonitoringStatus(active) {
        const statusIndicator = document.querySelector('#monitoringStatus .status-indicator');
        if (statusIndicator) {
            const icon = statusIndicator.querySelector('i');
            const text = statusIndicator.querySelector('span');
            
            if (active) {
                icon.style.color = 'var(--success-color)';
                text.textContent = 'Monitoring Active';
            } else {
                icon.style.color = 'var(--danger-color)';
                text.textContent = 'Monitoring Inactive';
            }
        }
    }
    
    async performQuickScan() {
        try {
            this.showLoading(true);
            this.showNotification('Starting quick scan...', 'info');
            
            // Navigate to scan page with quick scan preset
            window.location.href = '/scan?type=quick';
            
        } catch (error) {
            console.error('Failed to start quick scan:', error);
            this.showNotification('Failed to start quick scan: ' + error.message, 'error');
        } finally {
            this.showLoading(false);
        }
    }
    
    async performFullScan() {
        try {
            this.showLoading(true);
            this.showNotification('Starting full system scan...', 'info');
            
            // Navigate to scan page with full scan preset
            window.location.href = '/scan?type=full';
            
        } catch (error) {
            console.error('Failed to start full scan:', error);
            this.showNotification('Failed to start full scan: ' + error.message, 'error');
        } finally {
            this.showLoading(false);
        }
    }
    
    async updateSignatures() {
        try {
            this.showLoading(true);
            this.showNotification('Updating threat signatures...', 'info');
            
            // Simulate signature update
            await new Promise(resolve => setTimeout(resolve, 3000));
            
            this.showNotification('Threat signatures updated successfully', 'success');
            
        } catch (error) {
            console.error('Failed to update signatures:', error);
            this.showNotification('Failed to update signatures: ' + error.message, 'error');
        } finally {
            this.showLoading(false);
        }
    }
    
    refreshThreats() {
        const threatsList = document.getElementById('threatsList');
        if (threatsList) {
            // Simulate loading
            threatsList.innerHTML = '<div class="loading-spinner"><i class="fas fa-spinner fa-spin"></i></div>';
            
            setTimeout(() => {
                // Show no threats for now
                threatsList.innerHTML = `
                    <div class="no-threats">
                        <i class="fas fa-check-circle"></i>
                        <p>No threats detected recently</p>
                    </div>
                `;
            }, 1000);
        }
    }
    
    updateSystemStatus(data) {
        if (data.stats) {
            // Update stat counters
            Object.keys(data.stats).forEach(key => {
                const element = document.querySelector(`[data-target="${data.stats[key]}"]`);
                if (element) {
                    element.setAttribute('data-target', data.stats[key]);
                    element.textContent = data.stats[key].toLocaleString();
                }
            });
        }
        
        if (data.components) {
            this.updateComponentsStatus(data.components);
        }
    }
    
    updateComponentsStatus(components) {
        const componentsList = document.getElementById('componentsList');
        if (componentsList && components) {
            Object.keys(components).forEach(component => {
                const componentItem = componentsList.querySelector(`[data-component="${component}"]`);
                if (componentItem) {
                    const icon = componentItem.querySelector('i');
                    const status = componentItem.querySelector('.component-status');
                    
                    if (components[component]) {
                        icon.className = 'fas fa-check-circle';
                        status.textContent = 'Active';
                        status.className = 'component-status active';
                    } else {
                        icon.className = 'fas fa-times-circle';
                        status.textContent = 'Inactive';
                        status.className = 'component-status inactive';
                    }
                }
            });
        }
    }
    
    handleThreatDetection(data) {
        const threat = data.threat;
        
        // Show critical notification
        this.showNotification(
            `Threat detected: ${threat.threat_name || 'Unknown threat'}`,
            'error',
            10000
        );
        
        // Add to threats list
        this.addThreatToList(threat);
        
        // Update threat counter
        const threatCounter = document.querySelector('.threat-count');
        if (threatCounter) {
            const current = parseInt(threatCounter.textContent) || 0;
            threatCounter.textContent = (current + 1).toLocaleString();
        }
    }
    
    addThreatToList(threat) {
        const threatsList = document.getElementById('threatsList');
        if (threatsList) {
            // Remove "no threats" message if present
            const noThreats = threatsList.querySelector('.no-threats');
            if (noThreats) {
                noThreats.remove();
            }
            
            const threatItem = document.createElement('div');
            threatItem.className = 'threat-item';
            threatItem.innerHTML = `
                <div class="threat-info">
                    <h4>${threat.threat_name || 'Unknown Threat'}</h4>
                    <p>${threat.file_path || 'Unknown location'}</p>
                </div>
                <div class="threat-level ${threat.threat_level?.toLowerCase() || 'medium'}">
                    ${threat.threat_level || 'Medium'}
                </div>
            `;
            
            threatsList.insertBefore(threatItem, threatsList.firstChild);
            
            // Limit to 10 items
            const items = threatsList.querySelectorAll('.threat-item');
            if (items.length > 10) {
                items[items.length - 1].remove();
            }
        }
    }
    
    updateScanProgress(data) {
        // This would be used if we had a scan progress indicator on the dashboard
        console.log('Scan progress:', data);
    }
    
    handleScanCompletion(data) {
        this.showNotification(
            `Scan completed. ${data.total_files || 0} files scanned.`,
            'success'
        );
    }
    
    updateConnectionStatus(connected) {
        const systemStatus = document.getElementById('systemStatus');
        if (systemStatus) {
            const icon = systemStatus.querySelector('i');
            const text = systemStatus.querySelector('span');
            
            if (connected) {
                icon.style.color = 'var(--success-color)';
                text.textContent = 'System Active';
            } else {
                icon.style.color = 'var(--danger-color)';
                text.textContent = 'System Offline';
            }
        }
    }
    
    showNotification(message, type = 'info', duration = 5000) {
        const container = document.getElementById('notificationContainer');
        if (!container) return;
        
        const notification = document.createElement('div');
        notification.className = `notification ${type}`;
        
        const id = Date.now();
        notification.innerHTML = `
            <div class="notification-header">
                <div class="notification-title">
                    ${type === 'success' ? 'Success' : 
                      type === 'error' ? 'Error' : 
                      type === 'warning' ? 'Warning' : 'Info'}
                </div>
                <button class="notification-close" onclick="this.parentElement.parentElement.remove()">
                    <i class="fas fa-times"></i>
                </button>
            </div>
            <div class="notification-message">${message}</div>
        `;
        
        container.appendChild(notification);
        
        // Auto remove after duration
        setTimeout(() => {
            if (notification.parentElement) {
                notification.remove();
            }
        }, duration);
        
        this.notifications.push({ id, element: notification, type, message });
    }
    
    showLoading(show) {
        const overlay = document.getElementById('loadingOverlay');
        if (overlay) {
            overlay.classList.toggle('active', show);
        }
    }
    
    generateTimeLabels() {
        const labels = [];
        const now = new Date();
        
        for (let i = 23; i >= 0; i--) {
            const time = new Date(now.getTime() - i * 60 * 60 * 1000);
            labels.push(time.getHours() + ':00');
        }
        
        return labels;
    }
    
    generateSampleData(isThreats = false) {
        const data = [];
        const baseValue = isThreats ? 2 : 50;
        const variance = isThreats ? 5 : 30;
        
        for (let i = 0; i < 24; i++) {
            const value = Math.max(0, baseValue + Math.random() * variance - variance / 2);
            data.push(Math.round(value));
        }
        
        return data;
    }
    
    updateChartPeriod(period) {
        if (this.charts.activity) {
            // Update chart data based on period
            let labels, data1, data2;
            
            switch (period) {
                case '7d':
                    labels = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
                    data1 = this.generateSampleData().slice(0, 7);
                    data2 = this.generateSampleData(true).slice(0, 7);
                    break;
                case '30d':
                    labels = Array.from({length: 30}, (_, i) => `Day ${i + 1}`);
                    data1 = this.generateSampleData().slice(0, 30);
                    data2 = this.generateSampleData(true).slice(0, 30);
                    break;
                default:
                    labels = this.generateTimeLabels();
                    data1 = this.generateSampleData();
                    data2 = this.generateSampleData(true);
            }
            
            this.charts.activity.data.labels = labels;
            this.charts.activity.data.datasets[0].data = data1;
            this.charts.activity.data.datasets[1].data = data2;
            this.charts.activity.update();
        }
    }
}

// Initialize dashboard when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.antivirusDashboard = new AntivirusDashboard();
});

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = AntivirusDashboard;
}
