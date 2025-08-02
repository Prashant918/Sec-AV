/**
 * Prashant918 Advanced Antivirus - Scan Page JavaScript
 * Handles scanning operations, progress tracking, and results display
 */

class AntivirusScanManager {
    constructor() {
        this.socket = null;
        this.currentScan = null;
        this.scanHistory = [];
        this.selectedTargets = [];
        this.scanStartTime = null;
        this.elapsedTimer = null;
        
        this.init();
    }
    
    init() {
        this.initializeWebSocket();
        this.initializeEventListeners();
        this.loadScanHistory();
        this.checkUrlParams();
        
        console.log('Antivirus Scan Manager initialized');
    }
    
    initializeWebSocket() {
        try {
            this.socket = io();
            
            this.socket.on('connect', () => {
                console.log('Connected to antivirus server');
                this.updateConnectionStatus(true);
            });
            
            this.socket.on('disconnect', () => {
                console.log('Disconnected from antivirus server');
                this.updateConnectionStatus(false);
            });
            
            this.socket.on('scan_progress', (data) => {
                this.updateScanProgress(data);
            });

            this.socket.on('scan_completed', (data) => {
                this.handleScanCompletion(data);
            });
            
            this.socket.on('threat_detected', (data) => {
                this.handleThreatDetection(data);
            });
            
        } catch (error) {
            console.error('WebSocket initialization failed:', error);
            this.showNotification('Real-time updates unavailable', 'error');
        }
    }
    
    initializeEventListeners() {
        // Theme toggle
        const themeToggle = document.getElementById('themeToggle');
        if (themeToggle) {
            themeToggle.addEventListener('click', () => this.toggleTheme());
        }
        
        // Scan type buttons
        document.getElementById('quickScanBtn')?.addEventListener('click', () => this.startQuickScan());
        document.getElementById('fullScanBtn')?.addEventListener('click', () => this.startFullScan());
        document.getElementById('customScanBtn')?.addEventListener('click', () => this.showCustomScanConfig());
        
        // Custom scan configuration
        document.getElementById('closeConfig')?.addEventListener('click', () => this.hideCustomScanConfig());
        document.getElementById('browseBtn')?.addEventListener('click', () => this.showFileBrowser());
        document.getElementById('startCustomScan')?.addEventListener('click', () => this.startCustomScan());
        document.getElementById('cancelCustomScan')?.addEventListener('click', () => this.hideCustomScanConfig());
        
        // Scan path input
        const scanPathInput = document.getElementById('scanPath');
        if (scanPathInput) {
            scanPathInput.addEventListener('keypress', (e) => {
                if (e.key === 'Enter') {
                    this.addScanTarget(e.target.value);
                    e.target.value = '';
                }
            });
        }
        
        // Progress controls
        document.getElementById('stopScanBtn')?.addEventListener('click', () => this.stopScan());
        document.getElementById('clearActivity')?.addEventListener('click', () => this.clearActivity());
        
        // Results controls
        document.getElementById('newScanBtn')?.addEventListener('click', () => this.startNewScan());
        document.getElementById('exportResultsBtn')?.addEventListener('click', () => this.exportResults());
        document.getElementById('resultFilter')?.addEventListener('change', (e) => this.filterResults(e.target.value));
        document.getElementById('searchResults')?.addEventListener('input', (e) => this.searchResults(e.target.value));
        
        // History controls
        document.getElementById('refreshHistory')?.addEventListener('click', () => this.loadScanHistory());
        
        // File browser modal
        document.getElementById('closeBrowserModal')?.addEventListener('click', () => this.hideFileBrowser());
        document.getElementById('cancelBrowser')?.addEventListener('click', () => this.hideFileBrowser());
        document.getElementById('selectPath')?.addEventListener('click', () => this.selectBrowserPath());
        document.getElementById('browserBack')?.addEventListener('click', () => this.browserNavigateBack());
        document.getElementById('browserHome')?.addEventListener('click', () => this.browserNavigateHome());
    }
    
    checkUrlParams() {
        const urlParams = new URLSearchParams(window.location.search);
        const scanType = urlParams.get('type');
        
        if (scanType === 'quick') {
            setTimeout(() => this.startQuickScan(), 500);
        } else if (scanType === 'full') {
            setTimeout(() => this.startFullScan(), 500);
        }
    }
    
    toggleTheme() {
        const currentTheme = document.documentElement.getAttribute('data-theme') || 'light';
        const newTheme = currentTheme === 'light' ? 'dark' : 'light';
        
        document.documentElement.setAttribute('data-theme', newTheme);
        localStorage.setItem('theme', newTheme);
        
        const themeToggle = document.getElementById('themeToggle');
        const icon = themeToggle.querySelector('i');
        icon.className = newTheme === 'dark' ? 'fas fa-sun' : 'fas fa-moon';
        
        this.showNotification(`Switched to ${newTheme} theme`, 'info');
    }
    
    async startQuickScan() {
        try {
            this.showLoading(true);
            
            const commonPaths = this.getCommonScanPaths();
            await this.initiateScan('quick', commonPaths, {
                recursive: true,
                quarantine: true,
                deepScan: false
            });
            
        } catch (error) {
            console.error('Failed to start quick scan:', error);
            this.showNotification('Failed to start quick scan: ' + error.message, 'error');
        } finally {
            this.showLoading(false);
        }
    }
    
    async startFullScan() {
        try {
            this.showLoading(true);
            
            const systemPaths = this.getSystemScanPaths();
            await this.initiateScan('full', systemPaths, {
                recursive: true,
                quarantine: true,
                deepScan: true
            });
            
        } catch (error) {
            console.error('Failed to start full scan:', error);
            this.showNotification('Failed to start full scan: ' + error.message, 'error');
        } finally {
            this.showLoading(false);
        }
    }
    
    showCustomScanConfig() {
        const configSection = document.getElementById('customScanConfig');
        if (configSection) {
            configSection.style.display = 'block';
            configSection.scrollIntoView({ behavior: 'smooth' });
        }
    }
    
    hideCustomScanConfig() {
        const configSection = document.getElementById('customScanConfig');
        if (configSection) {
            configSection.style.display = 'none';
        }
        this.selectedTargets = [];
        this.updateTargetList();
    }
    
    async startCustomScan() {
        if (this.selectedTargets.length === 0) {
            this.showNotification('Please select at least one file or folder to scan', 'warning');
            return;
        }
        
        try {
            this.showLoading(true);
            
            const options = {
                recursive: document.getElementById('recursiveScan')?.checked || false,
                quarantine: document.getElementById('quarantineThreats')?.checked || false,
                deepScan: document.getElementById('deepScan')?.checked || false
            };
            
            await this.initiateScan('custom', this.selectedTargets, options);
            this.hideCustomScanConfig();
            
        } catch (error) {
            console.error('Failed to start custom scan:', error);
            this.showNotification('Failed to start custom scan: ' + error.message, 'error');
        } finally {
            this.showLoading(false);
        }
    }
    
    async initiateScan(type, paths, options) {
        const scanData = {
            type: type,
            paths: paths,
            options: options
        };
        
        // Start scan for each path
        const scanPromises = paths.map(async (path) => {
            const response = await fetch('/api/scan/directory', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    directory_path: path,
                    recursive: options.recursive
                })
            });
            
            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.error || 'Scan failed');
            }
            
            return response.json();
        });
        
        const results = await Promise.all(scanPromises);
        
        // Use the first scan ID for tracking
        if (results.length > 0) {
            this.currentScan = {
                id: results[0].scan_id,
                type: type,
                paths: paths,
                options: options,
                startTime: new Date(),
                status: 'running'
            };
            
            this.showScanProgress();
            this.startElapsedTimer();
            this.showNotification(`${type.charAt(0).toUpperCase() + type.slice(1)} scan started`, 'success');
        }
    }
    
    showScanProgress() {
        // Hide other sections
        document.getElementById('scanResultsSection').style.display = 'none';
        
        // Show progress section
        const progressSection = document.getElementById('scanProgressSection');
        if (progressSection) {
            progressSection.style.display = 'block';
            progressSection.scrollIntoView({ behavior: 'smooth' });
        }
        
        // Update progress title
        const progressTitle = document.getElementById('scanProgressTitle');
        if (progressTitle && this.currentScan) {
            progressTitle.textContent = `${this.currentScan.type.charAt(0).toUpperCase() + this.currentScan.type.slice(1)} Scan in Progress...`;
        }
        
        // Reset progress indicators
        this.updateProgressBar(0);
        this.updateScanStats(0, 0, '-');
        this.clearActivity();
    }
    
    updateScanProgress(data) {
        if (!this.currentScan || data.scan_id !== this.currentScan.id) {
            return;
        }
        
        // Update progress bar
        this.updateProgressBar(data.progress || 0);
        
        // Update current file
        const currentFileElement = document.getElementById('currentFile');
        if (currentFileElement && data.current_file) {
            currentFileElement.textContent = this.truncatePath(data.current_file, 50);
            currentFileElement.title = data.current_file;
        }
        
        // Add activity item
        if (data.current_file) {
            this.addActivityItem('scanning', `Scanning: ${this.truncatePath(data.current_file, 60)}`, new Date());
        }
    }
    
    handleScanCompletion(data) {
        if (!this.currentScan) {
            return;
        }
        
        this.currentScan.status = 'completed';
        this.currentScan.endTime = new Date();
        this.currentScan.results = data;
        
        this.stopElapsedTimer();
        this.showScanResults(data);
        this.addToScanHistory(this.currentScan);
        
        this.showNotification('Scan completed successfully', 'success');
    }
    
    handleThreatDetection(data) {
        const threat = data.threat;
        
        // Update threat counter
        const threatsFoundElement = document.getElementById('threatsFound');
        if (threatsFoundElement) {
            const current = parseInt(threatsFoundElement.textContent) || 0;
            threatsFoundElement.textContent = current + 1;
        }
        
        // Add threat activity
        this.addActivityItem('threat', `Threat detected: ${threat.threat_name || 'Unknown'} in ${this.truncatePath(threat.file_path, 40)}`, new Date());
        
        // Show critical notification
        this.showNotification(`Threat detected: ${threat.threat_name || 'Unknown threat'}`, 'error', 10000);
    }
    
    updateProgressBar(percentage) {
        const progressFill = document.getElementById('progressFill');
        const progressPercent = document.getElementById('progressPercent');
        
        if (progressFill) {
            progressFill.style.width = `${percentage}%`;
        }
        
        if (progressPercent) {
            progressPercent.textContent = `${Math.round(percentage)}%`;
        }
    }
    
    updateScanStats(filesScanned, threatsFound, currentFile) {
        const filesScannedElement = document.getElementById('filesScanned');
        const threatsFoundElement = document.getElementById('threatsFound');
        const currentFileElement = document.getElementById('currentFile');
        
        if (filesScannedElement) {
            filesScannedElement.textContent = filesScanned.toLocaleString();
        }
        
        if (threatsFoundElement) {
            threatsFoundElement.textContent = threatsFound.toLocaleString();
        }
        
        if (currentFileElement) {
            currentFileElement.textContent = currentFile;
        }
    }
    
    startElapsedTimer() {
        this.scanStartTime = new Date();
        this.elapsedTimer = setInterval(() => {
            const elapsed = new Date() - this.scanStartTime;
            const minutes = Math.floor(elapsed / 60000);
            const seconds = Math.floor((elapsed % 60000) / 1000);
            
            const elapsedTimeElement = document.getElementById('elapsedTime');
            if (elapsedTimeElement) {
                elapsedTimeElement.textContent = `${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
            }
        }, 1000);
    }
    
    stopElapsedTimer() {
        if (this.elapsedTimer) {
            clearInterval(this.elapsedTimer);
            this.elapsedTimer = null;
        }
    }
    
    addActivityItem(type, text, timestamp) {
        const activityList = document.getElementById('activityList');
        if (!activityList) return;
        
        const activityItem = document.createElement('div');
        activityItem.className = 'activity-item';
        
        const iconClass = type === 'threat' ? 'fas fa-exclamation-triangle' : 
                         type === 'clean' ? 'fas fa-check' : 'fas fa-search';
        
        activityItem.innerHTML = `
            <div class="activity-icon ${type}">
                <i class="${iconClass}"></i>
            </div>
            <div class="activity-text">${text}</div>
            <div class="activity-time">${timestamp.toLocaleTimeString()}</div>
        `;
        
        // Add to top of list
        activityList.insertBefore(activityItem, activityList.firstChild);
        
        // Limit to 50 items
        const items = activityList.querySelectorAll('.activity-item');
        if (items.length > 50) {
            items[items.length - 1].remove();
        }
        
        // Auto-scroll to top
        activityList.scrollTop = 0;
    }
    
    clearActivity() {
        const activityList = document.getElementById('activityList');
        if (activityList) {
            activityList.innerHTML = '';
        }
    }
    
    async stopScan() {
        if (!this.currentScan) {
            return;
        }
        
        try {
            // In a real implementation, you would call an API to stop the scan
            this.currentScan.status = 'stopped';
            this.stopElapsedTimer();
            
            this.showNotification('Scan stopped by user', 'warning');
            this.startNewScan();
            
        } catch (error) {
            console.error('Failed to stop scan:', error);
            this.showNotification('Failed to stop scan: ' + error.message, 'error');
        }
    }
    
    showScanResults(data) {
        // Hide progress section
        document.getElementById('scanProgressSection').style.display = 'none';
        
        // Show results section
        const resultsSection = document.getElementById('scanResultsSection');
        if (resultsSection) {
            resultsSection.style.display = 'block';
            resultsSection.scrollIntoView({ behavior: 'smooth' });
        }
        
        // Update results summary
        this.updateResultsSummary(data);
        
        // Populate results table
        this.populateResultsTable(data.results || []);
    }
    
    updateResultsSummary(data) {
        const summary = this.calculateSummary(data.results || []);
        
        document.getElementById('cleanFilesCount').textContent = summary.clean.toLocaleString();
        document.getElementById('threatFilesCount').textContent = summary.threats.toLocaleString();
        document.getElementById('quarantinedFilesCount').textContent = summary.quarantined.toLocaleString();
        document.getElementById('errorFilesCount').textContent = summary.errors.toLocaleString();
    }
    
    calculateSummary(results) {
        return results.reduce((summary, result) => {
            switch (result.status) {
                case 'clean':
                    summary.clean++;
                    break;
                case 'infected':
                case 'suspicious':
                    summary.threats++;
                    if (result.action === 'quarantined') {
                        summary.quarantined++;
                    }
                    break;
                case 'error':
                    summary.errors++;
                    break;
            }
            return summary;
        }, { clean: 0, threats: 0, quarantined: 0, errors: 0 });
    }
    
    populateResultsTable(results) {
        const tableBody = document.getElementById('resultsTableBody');
        if (!tableBody) return;
        
        tableBody.innerHTML = '';
        
        results.forEach(result => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td title="${result.file_path}">${this.truncatePath(result.file_path, 60)}</td>
                <td><span class="status-badge ${result.status}">${result.status}</span></td>
                <td>${result.threat_name || '-'}</td>
                <td>${result.action || '-'}</td>
                <td>
                    <button class="btn btn-sm" onclick="scanManager.showResultDetails('${result.file_path}')">
                        <i class="fas fa-info-circle"></i>
                    </button>
                </td>
            `;
            tableBody.appendChild(row);
        });
    }
    
    filterResults(filter) {
        const rows = document.querySelectorAll('#resultsTableBody tr');
        
        rows.forEach(row => {
            const statusBadge = row.querySelector('.status-badge');
            const status = statusBadge ? statusBadge.textContent.toLowerCase() : '';
            
            if (filter === 'all' || status.includes(filter)) {
                row.style.display = '';
            } else {
                row.style.display = 'none';
            }
        });
    }
    
    searchResults(query) {
        const rows = document.querySelectorAll('#resultsTableBody tr');
        const searchTerm = query.toLowerCase();
        
        rows.forEach(row => {
            const text = row.textContent.toLowerCase();
            if (text.includes(searchTerm)) {
                row.style.display = '';
            } else {
                row.style.display = 'none';
            }
        });
    }
    
    startNewScan() {
        // Hide all sections
        document.getElementById('scanProgressSection').style.display = 'none';
        document.getElementById('scanResultsSection').style.display = 'none';
        document.getElementById('customScanConfig').style.display = 'none';
        
        // Reset current scan
        this.currentScan = null;
        this.stopElapsedTimer();
        
        // Scroll to top
        window.scrollTo({ top: 0, behavior: 'smooth' });
    }
    
    async exportResults() {
        if (!this.currentScan || !this.currentScan.results) {
            this.showNotification('No results to export', 'warning');
            return;
        }
        
        try {
            const data = {
                scan: this.currentScan,
                timestamp: new Date().toISOString(),
                summary: this.calculateSummary(this.currentScan.results.results || [])
            };
            
            const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            
            const a = document.createElement('a');
            a.href = url;
            a.download = `scan_results_${new Date().toISOString().split('T')[0]}.json`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            
            URL.revokeObjectURL(url);
            
            this.showNotification('Results exported successfully', 'success');
            
        } catch (error) {
            console.error('Failed to export results:', error);
            this.showNotification('Failed to export results: ' + error.message, 'error');
        }
    }
    
    addScanTarget(path) {
        if (!path || path.trim() === '') {
            return;
        }
        
        path = path.trim();
        
        if (!this.selectedTargets.includes(path)) {
            this.selectedTargets.push(path);
            this.updateTargetList();
            this.showNotification(`Added scan target: ${this.truncatePath(path, 50)}`, 'success');
        } else {
            this.showNotification('Target already added', 'warning');
        }
    }
    
    removeScanTarget(path) {
        const index = this.selectedTargets.indexOf(path);
        if (index > -1) {
            this.selectedTargets.splice(index, 1);
            this.updateTargetList();
            this.showNotification(`Removed scan target: ${this.truncatePath(path, 50)}`, 'info');
        }
    }
    
    updateTargetList() {
        const targetList = document.getElementById('targetList');
        if (!targetList) return;
        
        if (this.selectedTargets.length === 0) {
            targetList.innerHTML = '<div style="padding: 1rem; text-align: center; color: var(--text-muted);">No targets selected</div>';
            return;
        }
        
        targetList.innerHTML = this.selectedTargets.map(path => `
            <div class="target-item">
                <div class="target-path">${path}</div>
                <button class="remove-target" onclick="scanManager.removeScanTarget('${path}')">
                    <i class="fas fa-times"></i>
                </button>
            </div>
        `).join('');
    }
    
    showFileBrowser() {
        const modal = document.getElementById('fileBrowserModal');
        if (modal) {
            modal.classList.add('active');
            this.loadBrowserContent('/');
        }
    }
    
    hideFileBrowser() {
        const modal = document.getElementById('fileBrowserModal');
        if (modal) {
            modal.classList.remove('active');
        }
    }
    
    loadBrowserContent(path) {
        // Simulate file browser content
        const browserContent = document.getElementById('browserContent');
        const currentPath = document.getElementById('currentPath');
        
        if (currentPath) {
            currentPath.textContent = path;
        }
        
        if (browserContent) {
            // Simulate directory listing
            const items = this.getSimulatedDirectoryListing(path);
            
            browserContent.innerHTML = items.map(item => `
                <div class="browser-item" data-path="${item.path}" data-type="${item.type}">
                    <i class="browser-icon fas fa-${item.type === 'directory' ? 'folder' : 'file'}"></i>
                    <div class="browser-name">${item.name}</div>
                    <div class="browser-size">${item.size || ''}</div>
                </div>
            `).join('');
            
            // Add click handlers
            browserContent.querySelectorAll('.browser-item').forEach(item => {
                item.addEventListener('click', () => {
                    const path = item.dataset.path;
                    const type = item.dataset.type;
                    
                    if (type === 'directory') {
                        this.loadBrowserContent(path);
                    } else {
                        // Select file
                        browserContent.querySelectorAll('.browser-item').forEach(i => i.classList.remove('selected'));
                        item.classList.add('selected');
                    }
                });
            });
        }
    }
    
    getSimulatedDirectoryListing(path) {
        // Simulate common directories and files
        const commonDirs = [
            { name: 'Desktop', path: '/Desktop', type: 'directory' },
            { name: 'Documents', path: '/Documents', type: 'directory' },
            { name: 'Downloads', path: '/Downloads', type: 'directory' },
            { name: 'Pictures', path: '/Pictures', type: 'directory' },
            { name: 'Videos', path: '/Videos', type: 'directory' }
        ];
        
        return commonDirs;
    }
    
    selectBrowserPath() {
        const selectedItem = document.querySelector('.browser-item.selected');
        if (selectedItem) {
            const path = selectedItem.dataset.path;
            this.addScanTarget(path);
            this.hideFileBrowser();
        } else {
            this.showNotification('Please select a file or folder', 'warning');
        }
    }
    
    browserNavigateBack() {
        const currentPath = document.getElementById('currentPath');
        if (currentPath) {
            const path = currentPath.textContent;
            const parentPath = path.split('/').slice(0, -1).join('/') || '/';
            this.loadBrowserContent(parentPath);
        }
    }
    
    browserNavigateHome() {
        this.loadBrowserContent('/');
    }
    
    loadScanHistory() {
        // Simulate loading scan history
        const historyList = document.getElementById('historyList');
        if (!historyList) return;
        
        // Generate sample history
        const sampleHistory = this.generateSampleHistory();
        
        if (sampleHistory.length === 0) {
            historyList.innerHTML = '<div style="padding: 2rem; text-align: center; color: var(--text-muted);">No scan history available</div>';
            return;
        }
        
        historyList.innerHTML = sampleHistory.map(scan => `
            <div class="history-item">
                <div class="history-info">
                    <div class="history-title">${scan.type.charAt(0).toUpperCase() + scan.type.slice(1)} Scan</div>
                    <div class="history-details">
                        <span><i class="fas fa-calendar"></i> ${scan.date}</span>
                        <span><i class="fas fa-clock"></i> ${scan.duration}</span>
                        <span><i class="fas fa-folder"></i> ${scan.paths} paths</span>
                    </div>
                </div>
                <div class="history-stats">
                    <div class="history-stat">
                        <span class="history-stat-value">${scan.filesScanned}</span>
                        <span class="history-stat-label">Files</span>
                    </div>
                    <div class="history-stat">
                        <span class="history-stat-value">${scan.threatsFound}</span>
                        <span class="history-stat-label">Threats</span>
                    </div>
                </div>
            </div>
        `).join('');
    }
    
    generateSampleHistory() {
        const history = [];
        const types = ['quick', 'full', 'custom'];
        
        for (let i = 0; i < 5; i++) {
            const date = new Date();
            date.setDate(date.getDate() - i);
            
            history.push({
                type: types[Math.floor(Math.random() * types.length)],
                date: date.toLocaleDateString(),
                duration: `${Math.floor(Math.random() * 30) + 5} min`,
                paths: Math.floor(Math.random() * 5) + 1,
                filesScanned: Math.floor(Math.random() * 10000) + 1000,
                threatsFound: Math.floor(Math.random() * 10)
            });
        }
        
        return history;
    }
    
    addToScanHistory(scan) {
        this.scanHistory.unshift(scan);
        
        // Keep only last 20 scans
        if (this.scanHistory.length > 20) {
            this.scanHistory = this.scanHistory.slice(0, 20);
        }
        
        // Update history display
        this.loadScanHistory();
    }
    
    getCommonScanPaths() {
        // Return common paths for quick scan
        const userHome = navigator.platform.includes('Win') ? 'C:\\Users\\' + (process.env.USERNAME || 'User') : '~';
        
        return [
            `${userHome}/Downloads`,
            `${userHome}/Desktop`,
            `${userHome}/Documents`
        ];
    }
    
    getSystemScanPaths() {
        // Return system paths for full scan
        if (navigator.platform.includes('Win')) {
            return ['C:\\', 'D:\\'];
        } else {
            return ['/', '/home', '/usr', '/var'];
        }
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
    }
    
    showLoading(show) {
        const overlay = document.getElementById('loadingOverlay');
        if (overlay) {
            overlay.classList.toggle('active', show);
        }
    }
    
    truncatePath(path, maxLength) {
        if (path.length <= maxLength) {
            return path;
        }
        
        const start = path.substring(0, Math.floor(maxLength / 2) - 2);
        const end = path.substring(path.length - Math.floor(maxLength / 2) + 2);
        
        return `${start}...${end}`;
    }
    
    showResultDetails(filePath) {
        // Show detailed information about a scan result
        this.showNotification(`Detailed view for: ${this.truncatePath(filePath, 50)}`, 'info');
    }
}

// Initialize scan manager when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    // Initialize theme
    const savedTheme = localStorage.getItem('theme') || 'light';
    document.documentElement.setAttribute('data-theme', savedTheme);
    
    const themeToggle = document.getElementById('themeToggle');
    if (themeToggle) {
        const icon = themeToggle.querySelector('i');
        icon.className = savedTheme === 'dark' ? 'fas fa-sun' : 'fas fa-moon';
    }
    
    // Initialize scan manager
    window.scanManager = new AntivirusScanManager();
});

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = AntivirusScanManager;
}