// Prashant918 Advanced Antivirus - Main JavaScript
class AntivirusWebInterface {
    constructor() {
        this.isAuthenticated = false;
        this.apiKey = null;
        this.debugMode = false;
        this.systemStats = {
            threatsBlocked: 1247,
            filesScanned: 45892,
            systemStatus: 'active'
        };
        
        this.init();
    }

    init() {
        this.setupEventListeners();
        this.startLoadingSequence();
        this.initializeAnimations();
        this.setupNavigation();
        this.loadSystemStats();
    }

    setupEventListeners() {
        // Navigation
        document.addEventListener('DOMContentLoaded', () => {
            this.setupSmoothScrolling();
            this.setupMobileMenu();
        });

        // Admin login
        const adminForm = document.getElementById('adminLoginForm');
        if (adminForm) {
            adminForm.addEventListener('submit', (e) => this.handleAdminLogin(e));
        }

        // API navigation
        document.querySelectorAll('.api-nav-item').forEach(item => {
            item.addEventListener('click', (e) => this.switchApiSection(e));
        });

        // Tab navigation
        document.querySelectorAll('.tab-btn').forEach(btn => {
            btn.addEventListener('click', (e) => this.switchTab(e));
        });

        // Component details
        document.querySelectorAll('.component-item').forEach(item => {
            item.addEventListener('click', (e) => this.showComponentDetails(e));
        });

        // Debug console
        const debugInput = document.getElementById('debugCommand');
        if (debugInput) {
            debugInput.addEventListener('keypress', (e) => {
                if (e.key === 'Enter') {
                    this.executeDebugCommand();
                }
            });
        }

        // Window events
        window.addEventListener('scroll', () => this.handleScroll());
        window.addEventListener('resize', () => this.handleResize());
    }

    startLoadingSequence() {
        const loadingScreen = document.getElementById('loadingScreen');
        const progressBar = document.querySelector('.loading-progress');
        
        let progress = 0;
        const interval = setInterval(() => {
            progress += Math.random() * 15;
            if (progress >= 100) {
                progress = 100;
                clearInterval(interval);
                setTimeout(() => {
                    loadingScreen.style.opacity = '0';
                    setTimeout(() => {
                        loadingScreen.style.display = 'none';
                        this.startCounterAnimations();
                    }, 500);
                }, 500);
            }
            progressBar.style.width = `${progress}%`;
        }, 200);
    }

    startCounterAnimations() {
        const counters = document.querySelectorAll('.stat-number');
        counters.forEach(counter => {
            const target = parseInt(counter.getAttribute('data-target'));
            const increment = target / 100;
            let current = 0;
            
            const timer = setInterval(() => {
                current += increment;
                if (current >= target) {
                    current = target;
                    clearInterval(timer);
                }
                
                if (target === 99.9) {
                    counter.textContent = current.toFixed(1) + '%';
                } else {
                    counter.textContent = Math.floor(current);
                }
            }, 20);
        });
    }

    initializeAnimations() {
        // Intersection Observer for scroll animations
        const observerOptions = {
            threshold: 0.1,
            rootMargin: '0px 0px -50px 0px'
        };

        const observer = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    entry.target.classList.add('fade-in-up');
                }
            });
        }, observerOptions);

        // Observe all feature cards and components
        document.querySelectorAll('.feature-card, .component-item, .doc-card').forEach(el => {
            observer.observe(el);
        });

        // Floating particles animation
        this.createFloatingParticles();
    }

    createFloatingParticles() {
        const particlesContainer = document.querySelector('.floating-particles');
        if (!particlesContainer) return;

        for (let i = 0; i < 20; i++) {
            const particle = document.createElement('div');
            particle.className = 'particle';
            particle.style.cssText = `
                position: absolute;
                width: 2px;
                height: 2px;
                background: var(--primary-color);
                border-radius: 50%;
                opacity: 0.6;
                left: ${Math.random() * 100}%;
                top: ${Math.random() * 100}%;
                animation: float ${3 + Math.random() * 4}s ease-in-out infinite;
                animation-delay: ${Math.random() * 2}s;
            `;
            particlesContainer.appendChild(particle);
        }
    }

    setupNavigation() {
        const navLinks = document.querySelectorAll('.nav-link');
        
        navLinks.forEach(link => {
            link.addEventListener('click', (e) => {
                e.preventDefault();
                const targetId = link.getAttribute('href').substring(1);
                
                if (targetId === 'admin') {
                    this.showAdminSection();
                } else {
                    this.scrollToSection(targetId);
                }
                
                // Update active nav link
                navLinks.forEach(l => l.classList.remove('active'));
                link.classList.add('active');
            });
        });
    }

    setupSmoothScrolling() {
        document.querySelectorAll('a[href^="#"]').forEach(anchor => {
            anchor.addEventListener('click', function (e) {
                e.preventDefault();
                const target = document.querySelector(this.getAttribute('href'));
                if (target) {
                    target.scrollIntoView({
                        behavior: 'smooth',
                        block: 'start'
                    });
                }
            });
        });
    }

    setupMobileMenu() {
        const navToggle = document.getElementById('navToggle');
        const navMenu = document.getElementById('navMenu');
        
        if (navToggle && navMenu) {
            navToggle.addEventListener('click', () => {
                navMenu.classList.toggle('active');
                navToggle.classList.toggle('active');
            });
        }
    }

    scrollToSection(sectionId) {
        const section = document.getElementById(sectionId);
        if (section) {
            const offsetTop = section.offsetTop - 70; // Account for fixed navbar
            window.scrollTo({
                top: offsetTop,
                behavior: 'smooth'
            });
        }
    }

    showAdminSection() {
        // Hide all other sections
        document.querySelectorAll('section').forEach(section => {
            if (section.id !== 'admin') {
                section.style.display = 'none';
            }
        });
        
        // Show admin section
        const adminSection = document.getElementById('admin');
        if (adminSection) {
            adminSection.style.display = 'block';
            this.scrollToSection('admin');
        }
    }

    handleAdminLogin(e) {
        e.preventDefault();
        const apiKeyInput = document.getElementById('apiKey');
        const enteredKey = apiKeyInput.value.trim();
        
        // Simulate API key validation (in real implementation, this would be server-side)
        const validApiKeys = [
            'P918AV_ADMIN_2024_SECURE_KEY_v1.0.2',
            'PRASHANT918_MASTER_ACCESS_TOKEN',
            'ADV_ANTIVIRUS_DEBUG_ACCESS_2024'
        ];
        
        if (validApiKeys.includes(enteredKey)) {
            this.isAuthenticated = true;
            this.apiKey = enteredKey;
            this.showAdminPanel();
            this.loadAdminData();
            
            // Show success message
            this.showNotification('Admin access granted', 'success');
        } else {
            this.showNotification('Invalid API key', 'error');
            apiKeyInput.value = '';
            
            // Add shake animation to form
            const loginForm = document.querySelector('.login-form');
            loginForm.style.animation = 'shake 0.5s ease-in-out';
            setTimeout(() => {
                loginForm.style.animation = '';
            }, 500);
        }
    }

    showAdminPanel() {
        document.getElementById('adminLogin').style.display = 'none';
        document.getElementById('adminPanel').style.display = 'block';
        
        // Initialize admin features
        this.initializeDebugConsole();
        this.loadSystemLogs();
        this.startRealTimeUpdates();
    }

    loadAdminData() {
        // Simulate loading admin data
        const stats = {
            systemStatus: 'Online',
            activeThreats: 0,
            filesScanned: 1247,
            quarantined: 23
        };
        
        // Update admin stats
        document.querySelectorAll('.stat-card .stat-number').forEach((el, index) => {
            const values = [stats.systemStatus, stats.activeThreats, stats.filesScanned, stats.quarantined];
            if (index < values.length) {
                el.textContent = values[index];
            }
        });
    }

    initializeDebugConsole() {
        const consoleOutput = document.getElementById('consoleOutput');
        if (!consoleOutput) return;
        
        // Add initial debug messages
        const initialMessages = [
            '[INFO] Debug console initialized',
            '[INFO] System monitoring active',
            '[INFO] Real-time protection enabled',
            '[DEBUG] ML models loaded successfully',
            '[INFO] Signature database updated',
            '[DEBUG] Memory scanner operational'
        ];
        
        initialMessages.forEach((msg, index) => {
            setTimeout(() => {
                this.addConsoleMessage(msg);
            }, index * 500);
        });
    }

    addConsoleMessage(message, type = 'info') {
        const consoleOutput = document.getElementById('consoleOutput');
        if (!consoleOutput) return;
        
        const timestamp = new Date().toLocaleTimeString();
        const line = document.createElement('div');
        line.className = 'console-line';
        line.innerHTML = `<span style="color: #666;">[${timestamp}]</span> ${message}`;
        
        // Color coding based on message type
        if (message.includes('[ERROR]')) {
            line.style.color = 'var(--error-color)';
        } else if (message.includes('[WARNING]')) {
            line.style.color = 'var(--warning-color)';
        } else if (message.includes('[SUCCESS]')) {
            line.style.color = 'var(--success-color)';
        }
        
        consoleOutput.appendChild(line);
        consoleOutput.scrollTop = consoleOutput.scrollHeight;
    }

    executeDebugCommand() {
        const input = document.getElementById('debugCommand');
        const command = input.value.trim();
        
        if (!command) return;
        
        // Add command to console
        this.addConsoleMessage(`> ${command}`, 'command');
        
        // Process debug commands
        this.processDebugCommand(command);
        
        input.value = '';
    }

    processDebugCommand(command) {
        const cmd = command.toLowerCase();
        
        switch (cmd) {
            case 'status':
                this.addConsoleMessage('[INFO] System Status: Online');
                this.addConsoleMessage('[INFO] Threat Engine: Active');
                this.addConsoleMessage('[INFO] Real-time Monitor: Running');
                break;
                
            case 'scan stats':
                this.addConsoleMessage(`[INFO] Files Scanned: ${this.systemStats.filesScanned}`);
                this.addConsoleMessage(`[INFO] Threats Blocked: ${this.systemStats.threatsBlocked}`);
                break;
                
            case 'memory usage':
                const memUsage = Math.floor(Math.random() * 30 + 40);
                this.addConsoleMessage(`[INFO] Memory Usage: ${memUsage}%`);
                break;
                
            case 'clear':
                this.clearConsole();
                break;
                
            case 'help':
                this.addConsoleMessage('[INFO] Available commands:');
                this.addConsoleMessage('  - status: Show system status');
                this.addConsoleMessage('  - scan stats: Show scanning statistics');
                this.addConsoleMessage('  - memory usage: Show memory usage');
                this.addConsoleMessage('  - clear: Clear console');
                this.addConsoleMessage('  - help: Show this help');
                break;
                
            default:
                this.addConsoleMessage(`[ERROR] Unknown command: ${command}`);
                this.addConsoleMessage('[INFO] Type "help" for available commands');
        }
    }

    clearConsole() {
        const consoleOutput = document.getElementById('consoleOutput');
        if (consoleOutput) {
            consoleOutput.innerHTML = '<div class="console-line">[INFO] Console cleared</div>';
        }
    }

    loadSystemLogs() {
        const logsContent = document.getElementById('logsContent');
        if (!logsContent) return;
        
        const sampleLogs = [
            '[2024-01-15 10:30:15] [INFO] System startup completed',
            '[2024-01-15 10:30:16] [INFO] Loading signature database...',
            '[2024-01-15 10:30:17] [SUCCESS] Signature database loaded (45,892 signatures)',
            '[2024-01-15 10:30:18] [INFO] Initializing ML models...',
            '[2024-01-15 10:30:20] [SUCCESS] ML models initialized successfully',
            '[2024-01-15 10:30:21] [INFO] Starting real-time monitoring...',
            '[2024-01-15 10:30:22] [SUCCESS] Real-time monitoring active',
            '[2024-01-15 10:31:45] [WARNING] Suspicious file detected: malware.exe',
            '[2024-01-15 10:31:46] [SUCCESS] File quarantined successfully',
            '[2024-01-15 10:32:10] [INFO] Signature update available',
            '[2024-01-15 10:32:15] [SUCCESS] Signatures updated (1,247 new signatures)'
        ];
        
        logsContent.innerHTML = sampleLogs.map(log => `<div class="log-line">${log}</div>`).join('');
    }

    startRealTimeUpdates() {
        // Simulate real-time updates
        setInterval(() => {
            if (this.isAuthenticated) {
                this.updateSystemStats();
                this.addRandomLogEntry();
            }
        }, 5000);
    }

    updateSystemStats() {
        // Simulate random stat updates
        this.systemStats.filesScanned += Math.floor(Math.random() * 10);
        
        if (Math.random() < 0.1) { // 10% chance of threat detection
            this.systemStats.threatsBlocked++;
            this.addConsoleMessage(`[WARNING] Threat detected and blocked! Total: ${this.systemStats.threatsBlocked}`);
        }
        
        // Update UI
        const statNumbers = document.querySelectorAll('.admin-stats .stat-number');
        if (statNumbers.length >= 3) {
            statNumbers[2].textContent = this.systemStats.filesScanned;
        }
    }

    addRandomLogEntry() {
        const randomLogs = [
            '[INFO] File scan completed: document.pdf - Clean',
            '[INFO] Network connection monitored: 192.168.1.100',
            '[DEBUG] Memory scan completed - No threats found',
            '[INFO] Signature database check - Up to date',
            '[DEBUG] System performance: CPU 15%, Memory 42%'
        ];
        
        const randomLog = randomLogs[Math.floor(Math.random() * randomLogs.length)];
        const timestamp = new Date().toLocaleString();
        const logEntry = `[${timestamp}] ${randomLog}`;
        
        const logsContent = document.getElementById('logsContent');
        if (logsContent) {
            const logLine = document.createElement('div');
            logLine.className = 'log-line';
            logLine.textContent = logEntry;
            logsContent.appendChild(logLine);
            logsContent.scrollTop = logsContent.scrollHeight;
        }
    }

    switchApiSection(e) {
        const targetSection = e.target.getAttribute('data-section');
        
        // Update nav items
        document.querySelectorAll('.api-nav-item').forEach(item => {
            item.classList.remove('active');
        });
        e.target.classList.add('active');
        
        // Update content sections
        document.querySelectorAll('.api-section').forEach(section => {
            section.classList.remove('active');
        });
        document.getElementById(targetSection).classList.add('active');
    }

    switchTab(e) {
        const targetTab = e.target.getAttribute('data-tab');
        
        // Update tab buttons
        document.querySelectorAll('.tab-btn').forEach(btn => {
            btn.classList.remove('active');
        });
        e.target.classList.add('active');
        
        // Update tab panes
        document.querySelectorAll('.tab-pane').forEach(pane => {
            pane.classList.remove('active');
        });
        document.getElementById(targetTab).classList.add('active');
    }

    showComponentDetails(e) {
        const componentItem = e.currentTarget;
        const componentName = componentItem.querySelector('h4').textContent;
        const componentPath = componentItem.querySelector('.component-path').textContent;
        const componentDesc = componentItem.querySelector('p').textContent;
        
        // Component details data
        const componentDetails = {
            'Advanced Threat Detection Engine': {
                description: 'Multi-layered threat detection engine with AI/ML capabilities',
                features: [
                    'Ensemble ML models (RandomForest, GradientBoosting, SVM, MLP)',
                    'Deep neural network for malware classification',
                    'YARA rule integration',
                    'Behavioral analysis',
                    'Heuristic detection',
                    'Real-time threat scoring'
                ],
                technologies: ['TensorFlow', 'Scikit-learn', 'YARA', 'NumPy'],
                api: '/api/v1/scan/file'
            },
            'Ensemble ML Detector': {
                description: 'Machine learning ensemble for advanced malware detection',
                features: [
                    'Multiple ML algorithms',
                    'Feature extraction from files',
                    'Behavioral pattern analysis',
                    'Zero-day threat detection',
                    'Continuous model updates'
                ],
                technologies: ['Scikit-learn', 'TensorFlow', 'NumPy', 'Pandas'],
                api: '/api/v1/ml/analyze'
            }
            // Add more component details as needed
        };
        
        const details = componentDetails[componentName] || {
            description: componentDesc,
            features: ['Advanced security features', 'Real-time monitoring', 'Threat detection'],
            technologies: ['Python', 'Machine Learning'],
            api: '/api/v1/component'
        };
        
        this.showModal(componentName, details);
    }

    showModal(title, details) {
        const modal = document.getElementById('componentModal');
        const modalTitle = document.getElementById('modalTitle');
        const modalBody = document.getElementById('modalBody');
        
        modalTitle.textContent = title;
        
        modalBody.innerHTML = `
            <div class="component-details">
                <p class="component-description">${details.description}</p>
                
                <h3>Key Features</h3>
                <ul class="feature-list">
                    ${details.features.map(feature => `<li>${feature}</li>`).join('')}
                </ul>
                
                <h3>Technologies</h3>
                <div class="tech-tags">
                    ${details.technologies.map(tech => `<span class="tech-tag">${tech}</span>`).join('')}
                </div>
                
                <h3>API Endpoint</h3>
                <div class="api-endpoint-info">
                    <code>${details.api}</code>
                </div>
            </div>
        `;
        
        modal.style.display = 'block';
    }

    closeModal() {
        document.getElementById('componentModal').style.display = 'none';
    }

    logout() {
        this.isAuthenticated = false;
        this.apiKey = null;
        
        // Reset admin section
        document.getElementById('adminPanel').style.display = 'none';
        document.getElementById('adminLogin').style.display = 'block';
        document.getElementById('apiKey').value = '';
        
        // Show all sections again
        document.querySelectorAll('section').forEach(section => {
            if (section.id !== 'admin') {
                section.style.display = 'block';
            }
        });
        
        // Navigate back to home
        this.scrollToSection('home');
        
        this.showNotification('Logged out successfully', 'info');
    }

    showNotification(message, type = 'info') {
        const notification = document.createElement('div');
        notification.className = `notification notification-${type}`;
        notification.textContent = message;
        
        notification.style.cssText = `
            position: fixed;
            top: 100px;
            right: 20px;
            padding: 1rem 2rem;
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: var(--border-radius);
            color: var(--text-primary);
            z-index: 10001;
            animation: slideInRight 0.3s ease-out;
        `;
        
        if (type === 'success') {
            notification.style.borderColor = 'var(--success-color)';
            notification.style.background = 'rgba(16, 185, 129, 0.1)';
        } else if (type === 'error') {
            notification.style.borderColor = 'var(--error-color)';
            notification.style.background = 'rgba(239, 68, 68, 0.1)';
        }
        
        document.body.appendChild(notification);
        
        setTimeout(() => {
            notification.style.animation = 'slideOutRight 0.3s ease-out';
            setTimeout(() => {
                document.body.removeChild(notification);
            }, 300);
        }, 3000);
    }

    handleScroll() {
        const navbar = document.getElementById('navbar');
        if (window.scrollY > 50) {
            navbar.style.background = 'rgba(10, 10, 10, 0.98)';
        } else {
            navbar.style.background = 'rgba(10, 10, 10, 0.95)';
        }
    }

    handleResize() {
        // Handle responsive behavior
        if (window.innerWidth <= 768) {
            // Mobile adjustments
        } else {
            // Desktop adjustments
        }
    }

    loadSystemStats() {
        // Simulate loading system statistics
        setTimeout(() => {
            this.updateThreatMonitor();
        }, 2000);
    }

    updateThreatMonitor() {
        const threatItems = document.querySelectorAll('.threat-item strong');
        if (threatItems.length >= 2) {
            // Animate numbers
            let malwareCount = 1247;
            let filesCount = 45892;
            
            const interval = setInterval(() => {
                malwareCount += Math.floor(Math.random() * 3);
                filesCount += Math.floor(Math.random() * 10);
                

                if (threatItems[0]) threatItems[0].textContent = malwareCount.toLocaleString();
                if (threatItems[1]) threatItems[1].textContent = filesCount.toLocaleString();
            }, 5000);
        }
    }

    openLiveDemo() {
        // Simulate opening a live demo
        this.showNotification('Live demo feature coming soon!', 'info');
        
        // Could integrate with actual demo environment
        setTimeout(() => {
            window.open('#', '_blank');
        }, 1000);
    }
}

// Global functions for HTML onclick handlers
function scrollToSection(sectionId) {
    antivirusInterface.scrollToSection(sectionId);
}

function showComponentDetails(componentId) {
    // This would be called from component items
    console.log('Showing details for:', componentId);
}

function closeModal() {
    antivirusInterface.closeModal();
}

function logout() {
    antivirusInterface.logout();
}

function clearConsole() {
    antivirusInterface.clearConsole();
}

function executeDebugCommand() {
    antivirusInterface.executeDebugCommand();
}

function openLiveDemo() {
    antivirusInterface.openLiveDemo();
}

// Initialize the interface when DOM is loaded
let antivirusInterface;
document.addEventListener('DOMContentLoaded', () => {
    antivirusInterface = new AntivirusWebInterface();
});

// Add CSS animations
const style = document.createElement('style');
style.textContent = `
    @keyframes slideInRight {
        from {
            transform: translateX(100%);
            opacity: 0;
        }
        to {
            transform: translateX(0);
            opacity: 1;
        }
    }
    
    @keyframes slideOutRight {
        from {
            transform: translateX(0);
            opacity: 1;
        }
        to {
            transform: translateX(100%);
            opacity: 0;
        }
    }
    
    @keyframes shake {
        0%, 100% { transform: translateX(0); }
        25% { transform: translateX(-5px); }
        75% { transform: translateX(5px); }
    }
    
    .particle {
        pointer-events: none;
    }
    
    .component-details {
        line-height: 1.6;
    }
    
    .component-description {
        font-size: 1.1rem;
        color: var(--text-secondary);
        margin-bottom: 2rem;
    }
    
    .feature-list {
        list-style: none;
        margin-bottom: 2rem;
    }
    
    .feature-list li {
        padding: 0.5rem 0;
        padding-left: 1.5rem;
        position: relative;
        color: var(--text-secondary);
    }
    
    .feature-list li::before {
        content: '✓';
        position: absolute;
        left: 0;
        color: var(--success-color);
        font-weight: bold;
    }
    
    .tech-tags {
        display: flex;
        flex-wrap: wrap;
        gap: 0.5rem;
        margin-bottom: 2rem;
    }
    
    .api-endpoint-info {
        background: var(--darker-bg);
        padding: 1rem;
        border-radius: 8px;
        border: 1px solid var(--border-color);
    }
    
    .api-endpoint-info code {
        color: var(--primary-color);
        font-family: 'JetBrains Mono', monospace;
    }
    
    .log-line {
        margin-bottom: 0.5rem;
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.9rem;
        color: var(--text-secondary);
    }
    
    .log-line:hover {
        background: rgba(0, 212, 255, 0.1);
        padding: 0.25rem;
        border-radius: 4px;
    }
`;
document.head.appendChild(style);