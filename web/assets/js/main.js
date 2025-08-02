/**
 * Main JavaScript for Prashant918 Advanced Antivirus Web Interface
 */

// Global state management
const AppState = {
    isAuthenticated: false,
    currentUser: null,
    systemStatus: {},
    threats: [],
    logs: []
};

// Utility functions
const Utils = {
    // Safe JSON parsing
    safeJsonParse: function(str, defaultValue = null) {
        try {
            return JSON.parse(str);
        } catch (e) {
            console.error('JSON parse error:', e);
            return defaultValue;
        }
    },

    // Safe object to string conversion
    objectToString: function(obj) {
        if (obj === null || obj === undefined) {
            return '';
        }
        if (typeof obj === 'string') {
            return obj;
        }
        if (typeof obj === 'object') {
            try {
                return JSON.stringify(obj, null, 2);
            } catch (e) {
                return '[Complex Object]';
            }
        }
        return String(obj);
    },

    // Format timestamp
    formatTimestamp: function(timestamp) {
        if (!timestamp) return 'N/A';
        const date = new Date(timestamp);
        return date.toLocaleString();
    },

    // Format file size
    formatFileSize: function(bytes) {
        if (!bytes || bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    },

    // Show notification
    showNotification: function(message, type = 'info') {
        const notification = document.createElement('div');
        notification.className = `notification notification-${type}`;
        notification.innerHTML = `
            <span>${this.objectToString(message)}</span>
            <button onclick="this.parentElement.remove()">&times;</button>
        `;
        
        document.body.appendChild(notification);
        
        // Auto remove after 5 seconds
        setTimeout(() => {
            if (notification.parentElement) {
                notification.remove();
            }
        }, 5000);
    }
};

// DOM manipulation helpers
const DOM = {
    // Safe element selection
    select: function(selector) {
        try {
            return document.querySelector(selector);
        } catch (e) {
            console.error('Selector error:', e);
            return null;
        }
    },

    // Safe element selection (all)
    selectAll: function(selector) {
        try {
            return document.querySelectorAll(selector);
        } catch (e) {
            console.error('Selector error:', e);
            return [];
        }
    },

    // Safe innerHTML setting
    setHTML: function(element, content) {
        if (!element) return;
        try {
            element.innerHTML = Utils.objectToString(content);
        } catch (e) {
            console.error('HTML setting error:', e);
            element.innerHTML = '[Error displaying content]';
        }
    },

    // Safe text content setting
    setText: function(element, content) {
        if (!element) return;
        try {
            element.textContent = Utils.objectToString(content);
        } catch (e) {
            console.error('Text setting error:', e);
            element.textContent = '[Error displaying content]';
        }
    }
};

// Loading screen management
const LoadingScreen = {
    show: function() {
        const loadingScreen = DOM.select('#loadingScreen');
        if (loadingScreen) {
            loadingScreen.style.display = 'flex';
        }
    },

    hide: function() {
        const loadingScreen = DOM.select('#loadingScreen');
        if (loadingScreen) {
            loadingScreen.style.display = 'none';
        }
    },

    updateProgress: function(progress, message = '') {
        const progressBar = DOM.select('.loading-progress');
        const loadingText = DOM.select('.loading-text');
        
        if (progressBar) {
            progressBar.style.width = `${progress}%`;
        }
        
        if (loadingText && message) {
            DOM.setText(loadingText, message);
        }
    }
};

// Navigation management
const Navigation = {
    init: function() {
        // Mobile menu toggle
        const navToggle = DOM.select('.nav-toggle');
        const navMenu = DOM.select('.nav-menu');
        
        if (navToggle && navMenu) {
            navToggle.addEventListener('click', () => {
                navMenu.classList.toggle('active');
            });
        }

        // Smooth scrolling for navigation links
        const navLinks = DOM.selectAll('.nav-link');
        navLinks.forEach(link => {
            link.addEventListener('click', (e) => {
                const href = link.getAttribute('href');
                if (href && href.startsWith('#')) {
                    e.preventDefault();
                    this.scrollToSection(href.substring(1));
                }
            });
        });
    },

    scrollToSection: function(sectionId) {
        const section = DOM.select(`#${sectionId}`);
        if (section) {
            section.scrollIntoView({
                behavior: 'smooth',
                block: 'start'
            });
        }
    }
};

// Admin panel management
const AdminPanel = {
    isLoggedIn: false,

    init: function() {
        const loginForm = DOM.select('#adminLoginForm');
        if (loginForm) {
            loginForm.addEventListener('submit', (e) => {
                e.preventDefault();
                this.handleLogin();
            });
        }

        // Initialize tabs
        this.initTabs();
    },

    handleLogin: function() {
        const apiKeyInput = DOM.select('#apiKey');
        if (!apiKeyInput) return;

        const apiKey = apiKeyInput.value.trim();
        if (!apiKey) {
            Utils.showNotification('Please enter an API key', 'error');
            return;
        }

        // Validate API key (you can customize this logic)
        if (this.validateApiKey(apiKey)) {
            this.showAdminPanel();
            this.loadDashboardData();
            Utils.showNotification('Login successful', 'success');
        } else {
            Utils.showNotification('Invalid API key', 'error');
        }
    },

    validateApiKey: function(apiKey) {
        // Simple validation - in production, this should be server-side
        const validKeys = [
            'admin123',
            'prashant918_admin',
            'dev_access_key',
            'demo_key'
        ];
        return validKeys.includes(apiKey);
    },

    showAdminPanel: function() {
        const loginSection = DOM.select('.admin-login');
        const panelSection = DOM.select('.admin-panel');
        
        if (loginSection) loginSection.style.display = 'none';
        if (panelSection) panelSection.style.display = 'block';
        
        this.isLoggedIn = true;
        AppState.isAuthenticated = true;
    },

    logout: function() {
        const loginSection = DOM.select('.admin-login');
        const panelSection = DOM.select('.admin-panel');
        
        if (loginSection) loginSection.style.display = 'block';
        if (panelSection) panelSection.style.display = 'none';
        
        this.isLoggedIn = false;
        AppState.isAuthenticated = false;
        
        // Clear sensitive data
        AppState.currentUser = null;
        AppState.systemStatus = {};
        
        Utils.showNotification('Logged out successfully', 'info');
    },

    initTabs: function() {
        const tabButtons = DOM.selectAll('.tab-btn');
        const tabPanes = DOM.selectAll('.tab-pane');

        tabButtons.forEach(button => {
            button.addEventListener('click', () => {
                const targetTab = button.getAttribute('data-tab');
                this.switchTab(targetTab);
            });
        });
    },

    switchTab: function(tabId) {
        // Update button states
        const tabButtons = DOM.selectAll('.tab-btn');
        tabButtons.forEach(btn => {
            btn.classList.remove('active');
            if (btn.getAttribute('data-tab') === tabId) {
                btn.classList.add('active');
            }
        });

        // Update pane visibility
        const tabPanes = DOM.selectAll('.tab-pane');
        tabPanes.forEach(pane => {
            pane.classList.remove('active');
            if (pane.id === tabId) {
                pane.classList.add('active');
            }
        });

        // Load tab-specific data
        this.loadTabData(tabId);
    },

    loadTabData: function(tabId) {
        switch (tabId) {
            case 'overview':
                this.loadDashboardData();
                break;
            case 'debug':
                this.loadDebugConsole();
                break;
            case 'logs':
                this.loadSystemLogs();
                break;
            case 'config':
                this.loadConfiguration();
                break;
        }
    },

    loadDashboardData: function() {
        // Simulate loading dashboard data
        const stats = {
            systemStatus: 'Active',
            activeThreats: Math.floor(Math.random() * 10),
            scannedFiles: Math.floor(Math.random() * 10000) + 50000,
            quarantinedFiles: Math.floor(Math.random() * 50) + 10
        };

        // Update dashboard elements
        const statusElement = DOM.select('#systemStatus');
        const threatsElement = DOM.select('#activeThreats');
        const scannedElement = DOM.select('#scannedFiles');
        const quarantinedElement = DOM.select('#quarantinedFiles');

        if (statusElement) DOM.setText(statusElement, stats.systemStatus);
        if (threatsElement) DOM.setText(threatsElement, stats.activeThreats);
        if (scannedElement) DOM.setText(scannedElement, stats.scannedFiles.toLocaleString());
        if (quarantinedElement) DOM.setText(quarantinedElement, stats.quarantinedFiles);

        AppState.systemStatus = stats;
    },

    loadDebugConsole: function() {
        const consoleOutput = DOM.select('#consoleOutput');
        if (consoleOutput) {
            const debugInfo = [
                '> System initialized successfully',
                '> Threat engine status: Active',
                '> Database connection: OK',
                '> Real-time monitoring: Enabled',
                '> Last signature update: ' + new Date().toLocaleString(),
                '> Memory usage: 245MB / 512MB',
                '> CPU usage: 12%'
            ];
            
            DOM.setHTML(consoleOutput, debugInfo.join('\n'));
        }
    },

    loadSystemLogs: function() {
        const logsContent = DOM.select('#logsContent');
        if (logsContent) {
            const sampleLogs = [
                { timestamp: new Date(), level: 'INFO', message: 'System started successfully' },
                { timestamp: new Date(Date.now() - 60000), level: 'WARNING', message: 'High memory usage detected' },
                { timestamp: new Date(Date.now() - 120000), level: 'INFO', message: 'Signature database updated' },
                { timestamp: new Date(Date.now() - 180000), level: 'ERROR', message: 'Failed to scan file: permission denied' }
            ];

            const logsHTML = sampleLogs.map(log => 
                `<div class="log-entry log-${log.level.toLowerCase()}">
                    <span class="log-timestamp">${Utils.formatTimestamp(log.timestamp)}</span>
                    <span class="log-level">${log.level}</span>
                    <span class="log-message">${Utils.objectToString(log.message)}</span>
                </div>`
            ).join('');

            DOM.setHTML(logsContent, logsHTML);
        }
    },

    loadConfiguration: function() {
        const configSections = DOM.selectAll('.config-section');
        configSections.forEach(section => {
            const inputs = section.querySelectorAll('input, select, textarea');
            inputs.forEach(input => {
                // Load default values or saved configuration
                if (input.type === 'checkbox') {
                    input.checked = Math.random() > 0.5; // Random for demo
                } else if (input.type === 'number') {
                    input.value = Math.floor(Math.random() * 100);
                }
            });
        });
    }
};

// Debug console functionality
const DebugConsole = {
    executeCommand: function() {
        const input = DOM.select('#debugInput');
        const output = DOM.select('#consoleOutput');
        
        if (!input || !output) return;
        
        const command = input.value.trim();
        if (!command) return;
        
        // Add command to output
        const currentOutput = output.textContent || '';
        const newOutput = currentOutput + '\n> ' + command + '\n';
        
        // Process command
        const result = this.processCommand(command);
        DOM.setText(output, newOutput + result + '\n');
        
        // Clear input
        input.value = '';
        
        // Scroll to bottom
        output.scrollTop = output.scrollHeight;
    },

    processCommand: function(command) {
        const cmd = command.toLowerCase().trim();
        
        switch (cmd) {
            case 'help':
                return 'Available commands: help, status, scan, clear, version, stats';
            case 'status':
                return 'System Status: Active\nThreats: 0\nLast Scan: ' + new Date().toLocaleString();
            case 'version':
                return 'Prashant918 Advanced Antivirus v1.0.2';
            case 'clear':
                setTimeout(() => {
                    const output = DOM.select('#consoleOutput');
                    if (output) DOM.setText(output, '');
                }, 100);
                return 'Console cleared.';
            case 'stats':
                return `Statistics:
- Files scanned: ${Math.floor(Math.random() * 10000)}
- Threats detected: ${Math.floor(Math.random() * 10)}
- Quarantined files: ${Math.floor(Math.random() * 5)}
- Uptime: ${Math.floor(Math.random() * 24)}h ${Math.floor(Math.random() * 60)}m`;
            default:
                return `Unknown command: ${command}. Type 'help' for available commands.`;
        }
    },

    clearConsole: function() {
        const output = DOM.select('#consoleOutput');
        if (output) {
            DOM.setText(output, '');
        }
    }
};

// Statistics animation
const StatsAnimation = {
    animateCounters: function() {
        const counters = DOM.selectAll('.stat-number');
        
        counters.forEach(counter => {
            const target = parseInt(counter.getAttribute('data-target')) || 0;
            const duration = 2000; // 2 seconds
            const step = target / (duration / 16); // 60fps
            let current = 0;
            
            const timer = setInterval(() => {
                current += step;
                if (current >= target) {
                    current = target;
                    clearInterval(timer);
                }
                
                DOM.setText(counter, Math.floor(current));
            }, 16);
        });
    }
};

// Global functions for HTML onclick handlers
window.scrollToSection = function(sectionId) {
    Navigation.scrollToSection(sectionId);
};

window.openLiveDemo = function() {
    Utils.showNotification('Live demo feature coming soon!', 'info');
};

window.logout = function() {
    AdminPanel.logout();
};

window.executeDebugCommand = function() {
    DebugConsole.executeCommand();
};

window.clearConsole = function() {
    DebugConsole.clearConsole();
};

// Initialize application
document.addEventListener('DOMContentLoaded', function() {
    console.log('Prashant918 Advanced Antivirus Web Interface Loading...');
    
    try {
        // Show loading screen
        LoadingScreen.show();
        LoadingScreen.updateProgress(20, 'Initializing interface...');
        
        // Initialize components
        setTimeout(() => {
            LoadingScreen.updateProgress(40, 'Loading navigation...');
            Navigation.init();
        }, 300);
        
        setTimeout(() => {
            LoadingScreen.updateProgress(60, 'Setting up admin panel...');
            AdminPanel.init();
        }, 600);
        
        setTimeout(() => {
            LoadingScreen.updateProgress(80, 'Starting animations...');
            StatsAnimation.animateCounters();
        }, 900);
        
        setTimeout(() => {
            LoadingScreen.updateProgress(100, 'Ready!');
            LoadingScreen.hide();
            Utils.showNotification('Welcome to Prashant918 Advanced Antivirus', 'success');
        }, 1200);
        
    } catch (error) {
        console.error('Initialization error:', error);
        LoadingScreen.hide();
        Utils.showNotification('Error initializing interface: ' + error.message, 'error');
    }
});

// Handle debug console enter key
document.addEventListener('keydown', function(e) {
    if (e.key === 'Enter' && e.target.id === 'debugInput') {
        e.preventDefault();
        DebugConsole.executeCommand();
    }
});

// Export for module usage
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        Utils,
        DOM,
        LoadingScreen,
        Navigation,
        AdminPanel,
        DebugConsole,
        StatsAnimation
    };
}
