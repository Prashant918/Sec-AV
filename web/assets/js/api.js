/**
 * API Handler for Prashant918 Advanced Antivirus
 */

const API = {
    baseURL: '/api/v1',
    timeout: 30000,
    
    // Make HTTP request with proper error handling
    request: async function(endpoint, options = {}) {
        const url = `${this.baseURL}${endpoint}`;
        const defaultOptions = {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
            },
            timeout: this.timeout
        };
        
        const config = { ...defaultOptions, ...options };
        
        try {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), config.timeout);
            
            const response = await fetch(url, {
                ...config,
                signal: controller.signal
            });
            
            clearTimeout(timeoutId);
            
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
            
            const data = await response.json();
            return { success: true, data };
            
        } catch (error) {
            console.error('API request failed:', error);
            return { 
                success: false, 
                error: error.message || 'Request failed',
                status: error.status || 0
            };
        }
    },
    
    // Authentication
    auth: {
        login: async function(apiKey) {
            return await API.request('/auth/login', {
                method: 'POST',
                body: JSON.stringify({ api_key: apiKey })
            });
        },
        
        logout: async function() {
            return await API.request('/auth/logout', {
                method: 'POST'
            });
        },
        
        verify: async function() {
            return await API.request('/auth/verify');
        }
    },
    
    // System operations
    system: {
        getStatus: async function() {
            return await API.request('/system/status');
        },
        
        getInfo: async function() {
            return await API.request('/system/info');
        },
        
        getStats: async function() {
            return await API.request('/system/stats');
        }
    },
    
    // Scanning operations
    scan: {
        scanFile: async function(filePath) {
            return await API.request('/scan/file', {
                method: 'POST',
                body: JSON.stringify({ file_path: filePath })
            });
        },
        
        scanDirectory: async function(dirPath, recursive = true) {
            return await API.request('/scan/directory', {
                method: 'POST',
                body: JSON.stringify({ 
                    directory_path: dirPath,
                    recursive: recursive
                })
            });
        },
        
        getResults: async function(scanId) {
            return await API.request(`/scan/results/${scanId}`);
        },
        
        getHistory: async function(limit = 100) {
            return await API.request(`/scan/history?limit=${limit}`);
        }
    },
    
    // Quarantine operations
    quarantine: {
        list: async function() {
            return await API.request('/quarantine/list');
        },
        
        restore: async function(quarantineId) {
            return await API.request(`/quarantine/restore/${quarantineId}`, {
                method: 'POST'
            });
        },
        
        delete: async function(quarantineId) {
            return await API.request(`/quarantine/delete/${quarantineId}`, {
                method: 'DELETE'
            });
        },
        
        getInfo: async function(quarantineId) {
            return await API.request(`/quarantine/info/${quarantineId}`);
        }
    },
    
    // Real-time monitoring
    monitor: {
        getStatus: async function() {
            return await API.request('/monitor/status');
        },
        
        start: async function(paths = []) {
            return await API.request('/monitor/start', {
                method: 'POST',
                body: JSON.stringify({ paths })
            });
        },
        
        stop: async function() {
            return await API.request('/monitor/stop', {
                method: 'POST'
            });
        },
        
        getThreats: async function(limit = 50) {
            return await API.request(`/monitor/threats?limit=${limit}`);
        }
    },
    
    // Configuration
    config: {
        get: async function(key = null) {
            const endpoint = key ? `/config/${key}` : '/config';
            return await API.request(endpoint);
        },
        
        set: async function(key, value) {
            return await API.request(`/config/${key}`, {
                method: 'PUT',
                body: JSON.stringify({ value })
            });
        },
        
        reset: async function() {
            return await API.request('/config/reset', {
                method: 'POST'
            });
        }
    },
    
    // Logs
    logs: {
        get: async function(level = 'all', limit = 100) {
            return await API.request(`/logs?level=${level}&limit=${limit}`);
        },
        
        clear: async function() {
            return await API.request('/logs/clear', {
                method: 'DELETE'
            });
        }
    }
};

// WebSocket connection for real-time updates
const WebSocketManager = {
    socket: null,
    reconnectAttempts: 0,
    maxReconnectAttempts: 5,
    reconnectDelay: 1000,
    
    connect: function() {
        try {
            const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
            const wsUrl = `${protocol}//${window.location.host}/ws`;
            
            this.socket = new WebSocket(wsUrl);
            
            this.socket.onopen = () => {
                console.log('WebSocket connected');
                this.reconnectAttempts = 0;
                Utils.showNotification('Real-time updates connected', 'success');
            };
            
            this.socket.onmessage = (event) => {
                try {
                    const data = JSON.parse(event.data);
                    this.handleMessage(data);
                } catch (error) {
                    console.error('WebSocket message parse error:', error);
                }
            };
            
            this.socket.onclose = () => {
                console.log('WebSocket disconnected');
                this.attemptReconnect();
            };
            
            this.socket.onerror = (error) => {
                console.error('WebSocket error:', error);
            };
            
        } catch (error) {
            console.error('WebSocket connection failed:', error);
        }
    },
    
    disconnect: function() {
        if (this.socket) {
            this.socket.close();
            this.socket = null;
        }
    },
    
    attemptReconnect: function() {
        if (this.reconnectAttempts < this.maxReconnectAttempts) {
            this.reconnectAttempts++;
            console.log(`Attempting to reconnect... (${this.reconnectAttempts}/${this.maxReconnectAttempts})`);
            
            setTimeout(() => {
                this.connect();
            }, this.reconnectDelay * this.reconnectAttempts);
        } else {
            Utils.showNotification('Real-time updates disconnected', 'warning');
        }
    },
    
    handleMessage: function(data) {
        switch (data.type) {
            case 'threat_detected':
                this.handleThreatAlert(data.payload);
                break;
            case 'scan_completed':
                this.handleScanComplete(data.payload);
                break;
            case 'system_status':
                this.handleSystemStatus(data.payload);
                break;
            case 'log_entry':
                this.handleLogEntry(data.payload);
                break;
            default:
                console.log('Unknown WebSocket message type:', data.type);
        }
    },
    
    handleThreatAlert: function(threat) {
        Utils.showNotification(`Threat detected: ${threat.name} in ${threat.file}`, 'error');
        
        // Update threat counter if visible
        const threatsElement = DOM.select('#activeThreats');
        if (threatsElement) {
            const current = parseInt(threatsElement.textContent) || 0;
            DOM.setText(threatsElement, current + 1);
        }
    },
    
    handleScanComplete: function(result) {
        Utils.showNotification(`Scan completed: ${result.files_scanned} files scanned`, 'info');
    },
    
    handleSystemStatus: function(status) {
        AppState.systemStatus = { ...AppState.systemStatus, ...status };
        
        // Update UI elements
        const statusElement = DOM.select('#systemStatus');
        if (statusElement && status.status) {
            DOM.setText(statusElement, status.status);
        }
    },
    
    handleLogEntry: function(logEntry) {
        // Add to logs if logs tab is active
        const logsContent = DOM.select('#logsContent');
        if (logsContent && AdminPanel.isLoggedIn) {
            const logHTML = `
                <div class="log-entry log-${logEntry.level.toLowerCase()}">
                    <span class="log-timestamp">${Utils.formatTimestamp(logEntry.timestamp)}</span>
                    <span class="log-level">${logEntry.level}</span>
                    <span class="log-message">${Utils.objectToString(logEntry.message)}</span>
                </div>
            `;
            logsContent.insertAdjacentHTML('afterbegin', logHTML);
            
            // Limit log entries to prevent memory issues
            const logEntries = logsContent.querySelectorAll('.log-entry');
            if (logEntries.length > 100) {
                logEntries[logEntries.length - 1].remove();
            }
        }
    }
};

// Initialize WebSocket when authenticated
document.addEventListener('DOMContentLoaded', function() {
    // Connect WebSocket after a delay to ensure page is loaded
    setTimeout(() => {
        if (typeof WebSocketManager !== 'undefined') {
            WebSocketManager.connect();
        }
    }, 2000);
});

// Export for module usage
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { API, WebSocketManager };
}
