// API Security Handler - JWT Guard Implementation
class APISecurityHandler {
    constructor() {
        this.jwtSecret = 'P918AV_JWT_SECRET_2024_ULTRA_SECURE';
        this.validApiKeys = new Set([
            'P918AV_ADMIN_2024_SECURE_KEY_v1.0.2',
            'PRASHANT918_MASTER_ACCESS_TOKEN',
            'ADV_ANTIVIRUS_DEBUG_ACCESS_2024'
        ]);
        
        this.rateLimits = new Map();
        this.blacklistedIPs = new Set();
        this.sessionTokens = new Map();
        
        this.init();
    }

    init() {
        this.setupAPIInterceptors();
        this.initializeRateLimiting();
        this.setupSecurityHeaders();
        this.startSecurityMonitoring();
    }

    setupAPIInterceptors() {
        // Intercept all API calls
        const originalFetch = window.fetch;
        
        window.fetch = async (url, options = {}) => {
            // Security validation for API calls
            if (this.isAPICall(url)) {
                const securityCheck = await this.validateAPIRequest(url, options);
                if (!securityCheck.valid) {
                    throw new Error(`API Security Error: ${securityCheck.reason}`);
                }
                
                // Add security headers
                options.headers = {
                    ...options.headers,
                    'X-Security-Token': this.generateSecurityToken(),
                    'X-Request-ID': this.generateRequestId(),
                    'X-Timestamp': Date.now().toString()
                };
            }
            
            return originalFetch.call(this, url, options);
        };
    }

    isAPICall(url) {
        return url.includes('/api/') || url.startsWith('api/');
    }

    async validateAPIRequest(url, options) {
        const clientIP = await this.getClientIP();
        
        // Check blacklisted IPs
        if (this.blacklistedIPs.has(clientIP)) {
            return { valid: false, reason: 'IP_BLACKLISTED' };
        }
        
        // Rate limiting check
        if (!this.checkRateLimit(clientIP)) {
            return { valid: false, reason: 'RATE_LIMIT_EXCEEDED' };
        }
        
        // Authentication check
        const authResult = this.validateAuthentication(options.headers);
        if (!authResult.valid) {
            return { valid: false, reason: authResult.reason };
        }
        
        // Request validation
        const requestValidation = this.validateRequestStructure(url, options);
        if (!requestValidation.valid) {
            return { valid: false, reason: requestValidation.reason };
        }
        
        return { valid: true };
    }

    async getClientIP() {
        // In a real implementation, this would get the actual client IP
        // For demo purposes, we'll simulate it
        return '192.168.1.100';
    }

    checkRateLimit(clientIP) {
        const now = Date.now();
        const windowMs = 60000; // 1 minute
        const maxRequests = 100;
        
        if (!this.rateLimits.has(clientIP)) {
            this.rateLimits.set(clientIP, { count: 1, resetTime: now + windowMs });
            return true;
        }
        
        const limit = this.rateLimits.get(clientIP);
        
        if (now > limit.resetTime) {
            // Reset window
            limit.count = 1;
            limit.resetTime = now + windowMs;
            return true;
        }
        
        if (limit.count >= maxRequests) {
            // Rate limit exceeded
            this.logSecurityEvent('RATE_LIMIT_EXCEEDED', { clientIP, count: limit.count });
            return false;
        }
        
        limit.count++;
        return true;
    }

    validateAuthentication(headers = {}) {
        const authHeader = headers['Authorization'] || headers['authorization'];
        const apiKeyHeader = headers['X-API-Key'] || headers['x-api-key'];
        
        // Check for API key authentication
        if (apiKeyHeader) {
            if (this.validApiKeys.has(apiKeyHeader)) {
                return { valid: true, method: 'API_KEY' };
            } else {
                this.logSecurityEvent('INVALID_API_KEY', { key: apiKeyHeader });
                return { valid: false, reason: 'INVALID_API_KEY' };
            }
        }
        
        // Check for JWT authentication
        if (authHeader && authHeader.startsWith('Bearer ')) {
            const token = authHeader.substring(7);
            const jwtValidation = this.validateJWT(token);
            if (jwtValidation.valid) {
                return { valid: true, method: 'JWT', payload: jwtValidation.payload };
            } else {
                return { valid: false, reason: 'INVALID_JWT' };
            }
        }
        
        // No valid authentication found
        return { valid: false, reason: 'NO_AUTHENTICATION' };
    }

    validateJWT(token) {
        try {
            // Simple JWT validation (in production, use a proper JWT library)
            const parts = token.split('.');
            if (parts.length !== 3) {
                return { valid: false, reason: 'MALFORMED_JWT' };
            }
            
            const header = JSON.parse(atob(parts[0]));
            const payload = JSON.parse(atob(parts[1]));
            const signature = parts[2];
            
            // Verify signature (simplified)
            const expectedSignature = this.generateJWTSignature(parts[0] + '.' + parts[1]);
            if (signature !== expectedSignature) {
                return { valid: false, reason: 'INVALID_SIGNATURE' };
            }
            
            // Check expiration
            if (payload.exp && payload.exp < Date.now() / 1000) {
                return { valid: false, reason: 'TOKEN_EXPIRED' };
            }
            
            return { valid: true, payload };
            
        } catch (error) {
            return { valid: false, reason: 'JWT_PARSE_ERROR' };
        }
    }

    generateJWTSignature(data) {
        // Simplified signature generation (use proper HMAC in production)
        let hash = 0;
        const combined = data + this.jwtSecret;
        for (let i = 0; i < combined.length; i++) {
            const char = combined.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash = hash & hash;
        }
        return btoa(hash.toString());
    }

    validateRequestStructure(url, options) {
        // Validate request method
        const method = options.method || 'GET';
        const allowedMethods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'];
        
        if (!allowedMethods.includes(method.toUpperCase())) {
            return { valid: false, reason: 'INVALID_METHOD' };
        }
        
        // Validate content type for POST/PUT requests
        if (['POST', 'PUT', 'PATCH'].includes(method.toUpperCase())) {
            const contentType = options.headers?.['Content-Type'] || options.headers?.['content-type'];
            if (!contentType) {
                return { valid: false, reason: 'MISSING_CONTENT_TYPE' };
            }
            
            const allowedContentTypes = [
                'application/json',
                'application/x-www-form-urlencoded',
                'multipart/form-data'
            ];
            
            if (!allowedContentTypes.some(type => contentType.includes(type))) {
                return { valid: false, reason: 'INVALID_CONTENT_TYPE' };
            }
        }
        
        // Validate URL structure
        if (!this.isValidAPIEndpoint(url)) {
            return { valid: false, reason: 'INVALID_ENDPOINT' };
        }
        
        return { valid: true };
    }

    isValidAPIEndpoint(url) {
        const validEndpoints = [
            '/api/v1/auth/login',
            '/api/v1/auth/logout',
            '/api/v1/scan/file',
            '/api/v1/scan/directory',
            '/api/v1/quarantine',
            '/api/v1/quarantine/restore',
            '/api/v1/quarantine/delete',
            '/api/v1/system/status',
            '/api/v1/system/stats',
            '/api/v1/admin/debug',
            '/api/v1/admin/logs',
            '/api/v1/admin/config'
        ];
        
        return validEndpoints.some(endpoint => url.includes(endpoint));
    }

    generateSecurityToken() {
        const timestamp = Date.now();
        const random = Math.random().toString(36).substring(2);
        const data = `${timestamp}-${random}`;
        return btoa(data);
    }

    generateRequestId() {
        return 'req_' + Math.random().toString(36).substr(2, 9) + '_' + Date.now();
    }

    initializeRateLimiting() {
        // Clean up old rate limit entries every 5 minutes
        setInterval(() => {
            const now = Date.now();
            for (const [ip, limit] of this.rateLimits.entries()) {
                if (now > limit.resetTime) {
                    this.rateLimits.delete(ip);
                }
            }
        }, 5 * 60 * 1000);
    }

    setupSecurityHeaders() {
        // Add security headers to all responses
        const originalFetch = window.fetch;
        
        window.fetch = async (...args) => {
            const response = await originalFetch.apply(this, args);
            
            // Clone response to add headers
            const clonedResponse = response.clone();
            
            // Add security headers
            const securityHeaders = {
                'X-Content-Type-Options': 'nosniff',
                'X-Frame-Options': 'DENY',
                'X-XSS-Protection': '1; mode=block',
                'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
                'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'",
                'Referrer-Policy': 'strict-origin-when-cross-origin'
            };
            
            // Note: In a real implementation, these headers would be set server-side
            console.log('Security headers applied:', securityHeaders);
            
            return response;
        };
    }

    startSecurityMonitoring() {
        // Monitor for suspicious activities
        setInterval(() => {
            this.performSecurityScan();
        }, 30000); // Every 30 seconds
        
        // Monitor for XSS attempts
        this.setupXSSProtection();
        
        // Monitor for CSRF attempts
        this.setupCSRFProtection();
    }

    performSecurityScan() {
        // Check for suspicious DOM modifications
        const suspiciousElements = document.querySelectorAll('script[src*="eval"], iframe[src*="javascript:"]');
        if (suspiciousElements.length > 0) {
            this.logSecurityEvent('SUSPICIOUS_DOM_MODIFICATION', {
                elements: suspiciousElements.length
            });
        }
        
        // Check for suspicious network activity
        if (this.rateLimits.size > 1000) {
            this.logSecurityEvent('HIGH_NETWORK_ACTIVITY', {
                uniqueIPs: this.rateLimits.size
            });
        }
        
        // Memory usage monitoring
        if (performance.memory) {
            const memoryUsage = performance.memory.usedJSHeapSize / performance.memory.totalJSHeapSize;
            if (memoryUsage > 0.9) {
                this.logSecurityEvent('HIGH_MEMORY_USAGE', {
                    usage: memoryUsage
                });
            }
        }
    }

    setupXSSProtection() {
        // Override dangerous DOM methods
        const originalInnerHTML = Element.prototype.innerHTML;
        Element.prototype.innerHTML = function(value) {
            if (typeof value === 'string' && this.isXSSAttempt(value)) {
                this.logSecurityEvent('XSS_ATTEMPT_BLOCKED', { content: value });
                throw new Error('XSS attempt blocked');
            }
            return originalInnerHTML.call(this, value);
        };
    }

    isXSSAttempt(content) {
        const xssPatterns = [
            /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
            /javascript:/gi,
            /on\w+\s*=/gi,
            /<iframe/gi,
            /<object/gi,
            /<embed/gi
        ];
        
        return xssPatterns.some(pattern => pattern.test(content));
    }

    setupCSRFProtection() {
        // Generate CSRF token
        this.csrfToken = this.generateCSRFToken();
        
        // Add CSRF token to all forms
        document.addEventListener('DOMContentLoaded', () => {
            this.addCSRFTokenToForms();
        });
        
        // Validate CSRF token on form submissions
        document.addEventListener('submit', (event) => {
            this.validateCSRFToken(event);
        });
    }

    generateCSRFToken() {
        const timestamp = Date.now();
        const random = Math.random().toString(36).substring(2);
        return btoa(`csrf_${timestamp}_${random}`);
    }

    addCSRFTokenToForms() {
        const forms = document.querySelectorAll('form');
        forms.forEach(form => {
            const csrfInput = document.createElement('input');
            csrfInput.type = 'hidden';
            csrfInput.name = '_csrf_token';
            csrfInput.value = this.csrfToken;
            form.appendChild(csrfInput);
        });
    }

    validateCSRFToken(event) {
        const form = event.target;
        const csrfInput = form.querySelector('input[name="_csrf_token"]');
        
        if (!csrfInput || csrfInput.value !== this.csrfToken) {
            event.preventDefault();
            this.logSecurityEvent('CSRF_ATTACK_BLOCKED', {
                form: form.action || 'unknown'
            });
            alert('Security error: Invalid CSRF token');
        }
    }

    logSecurityEvent(eventType, details) {
        const logEntry = {
            type: eventType,
            timestamp: new Date().toISOString(),
            details: details,
            userAgent: navigator.userAgent,
            url: window.location.href,
            sessionId: this.getSessionId()
        };
        
        // Store in local storage for admin review
        const securityLogs = JSON.parse(localStorage.getItem('apiSecurityLogs') || '[]');
        securityLogs.push(logEntry);
        
        // Keep only last 500 entries
        if (securityLogs.length > 500) {
            securityLogs.splice(0, securityLogs.length - 500);
        }
        
        localStorage.setItem('apiSecurityLogs', JSON.stringify(securityLogs));
        
        // Console logging for development
        console.warn('API Security Event:', logEntry);
    }

    getSessionId() {
        let sessionId = sessionStorage.getItem('apiSessionId');
        if (!sessionId) {
            sessionId = 'api_sess_' + Math.random().toString(36).substr(2, 9) + '_' + Date.now();
            sessionStorage.setItem('apiSessionId', sessionId);
        }
        return sessionId;
    }

    // Public API for admin access
    getSecurityLogs() {
        return JSON.parse(localStorage.getItem('apiSecurityLogs') || '[]');
    }

    clearSecurityLogs() {
        localStorage.removeItem('apiSecurityLogs');
        this.logSecurityEvent('API_LOGS_CLEARED', { clearedBy: 'admin' });
    }

    blacklistIP(ip) {
        this.blacklistedIPs.add(ip);
        this.logSecurityEvent('IP_BLACKLISTED', { ip });
    }

    whitelistIP(ip) {
        this.blacklistedIPs.delete(ip);
        this.logSecurityEvent('IP_WHITELISTED', { ip });
    }

    getRateLimitStatus() {
        const status = {};
        for (const [ip, limit] of this.rateLimits.entries()) {
            status[ip] = {
                count: limit.count,
                resetTime: new Date(limit.resetTime).toISOString()
            };
        }
        return status;
    }

    generateAdminToken(apiKey) {
        if (!this.validApiKeys.has(apiKey)) {
            throw new Error('Invalid API key');
        }
        
        const payload = {
            role: 'admin',
            apiKey: apiKey,
            iat: Math.floor(Date.now() / 1000),
            exp: Math.floor(Date.now() / 1000) + (24 * 60 * 60) // 24 hours
        };
        
        const header = { alg: 'HS256', typ: 'JWT' };
        const encodedHeader = btoa(JSON.stringify(header));
        const encodedPayload = btoa(JSON.stringify(payload));
        const signature = this.generateJWTSignature(encodedHeader + '.' + encodedPayload);
        
        return `${encodedHeader}.${encodedPayload}.${signature}`;
    }
}

// Initialize API security handler
const apiSecurityHandler = new APISecurityHandler();

// Export for legitimate admin access
window.APISecurityHandler = {
    getLogs: () => apiSecurityHandler.getSecurityLogs(),
    clearLogs: () => apiSecurityHandler.clearSecurityLogs(),
    blacklistIP: (ip) => apiSecurityHandler.blacklistIP(ip),
    whitelistIP: (ip) => apiSecurityHandler.whitelistIP(ip),
    getRateLimitStatus: () => apiSecurityHandler.getRateLimitStatus(),
    generateAdminToken: (apiKey) => apiSecurityHandler.generateAdminToken(apiKey)
};

// Protect the API handler from tampering
Object.freeze(window.APISecurityHandler);
