/**
 * Security utilities for Prashant918 Advanced Antivirus Web Interface
 */

const Security = {
    // Input sanitization
    sanitizeInput: function(input) {
        if (typeof input !== 'string') {
            return String(input);
        }
        
        return input
            .replace(/[<>]/g, '') // Remove potential HTML tags
            .replace(/javascript:/gi, '') // Remove javascript: protocol
            .replace(/on\w+=/gi, '') // Remove event handlers
            .trim();
    },
    
    // HTML escaping
    escapeHtml: function(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    },
    
    // Validate API key format
    validateApiKey: function(apiKey) {
        if (!apiKey || typeof apiKey !== 'string') {
            return false;
        }
        
        // Basic validation - adjust as needed
        return apiKey.length >= 8 && apiKey.length <= 64;
    },
    
    // Rate limiting for API calls
    rateLimiter: {
        requests: new Map(),
        
        isAllowed: function(endpoint, maxRequests = 10, windowMs = 60000) {
            const now = Date.now();
            const key = endpoint;
            
            if (!this.requests.has(key)) {
                this.requests.set(key, []);
            }
            
            const requests = this.requests.get(key);
            
            // Remove old requests outside the window
            const validRequests = requests.filter(time => now - time < windowMs);
            
            if (validRequests.length >= maxRequests) {
                return false;
            }
            
            validRequests.push(now);
            this.requests.set(key, validRequests);
            
            return true;
        }
    },
    
    // Session management
    session: {
        set: function(key, value, expirationMinutes = 60) {
            const expiration = new Date();
            expiration.setMinutes(expiration.getMinutes() + expirationMinutes);
            
            const sessionData = {
                value: value,
                expiration: expiration.getTime()
            };
            
            try {
                localStorage.setItem(`av_${key}`, JSON.stringify(sessionData));
                return true;
            } catch (error) {
                console.error('Session storage error:', error);
                return false;
            }
        },
        
        get: function(key) {
            try {
                const item = localStorage.getItem(`av_${key}`);
                if (!item) return null;
                
                const sessionData = JSON.parse(item);
                
                // Check expiration
                if (Date.now() > sessionData.expiration) {
                    this.remove(key);
                    return null;
                }
                
                return sessionData.value;
            } catch (error) {
                console.error('Session retrieval error:', error);
                return null;
            }
        },
        
        remove: function(key) {
            try {
                localStorage.removeItem(`av_${key}`);
                return true;
            } catch (error) {
                console.error('Session removal error:', error);
                return false;
            }
        },
        
        clear: function() {
            try {
                const keys = Object.keys(localStorage);
                keys.forEach(key => {
                    if (key.startsWith('av_')) {
                        localStorage.removeItem(key);
                    }
                });
                return true;
            } catch (error) {
                console.error('Session clear error:', error);
                return false;
            }
        }
    },
    
    // Content Security Policy helpers
    csp: {
        // Check if inline scripts are allowed
        inlineScriptsAllowed: function() {
            try {
                eval('1');
                return true;
            } catch (e) {
                return false;
            }
        },
        
        // Safe script execution
        safeEval: function(code) {
            try {
                return Function('"use strict"; return (' + code + ')')();
            } catch (error) {
                console.error('Safe eval error:', error);
                return null;
            }
        }
    },
    
    // Input validation
    validation: {
        isValidPath: function(path) {
            if (!path || typeof path !== 'string') return false;
            
            // Basic path validation
            const invalidChars = /[<>:"|?*]/;
            return !invalidChars.test(path) && path.length > 0 && path.length < 260;
        },
        
        isValidEmail: function(email) {
            const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
            return emailRegex.test(email);
        },
        
        isValidUrl: function(url) {
            try {
                new URL(url);
                return true;
            } catch {
                return false;
            }
        }
    }
};

// Secure event handling
const SecureEventHandler = {
    // Add event listener with security checks
    addListener: function(element, event, handler, options = {}) {
        if (!element || typeof handler !== 'function') {
            console.error('Invalid element or handler for event listener');
            return false;
        }
        
        const secureHandler = function(e) {
            try {
                // Basic security checks
                if (e.isTrusted === false && !options.allowUntrusted) {
                    console.warn('Untrusted event blocked');
                    return;
                }
                
                return handler.call(this, e);
            } catch (error) {
                console.error('Event handler error:', error);
                if (options.throwErrors) {
                    throw error;
                }
            }
        };
        
        element.addEventListener(event, secureHandler, options);
        return true;
    }
};

// Initialize security measures
document.addEventListener('DOMContentLoaded', function() {
    // Set up CSP violation reporting
    document.addEventListener('securitypolicyviolation', function(e) {
        console.warn('CSP Violation:', e.violatedDirective, e.blockedURI);
    });
    
    // Monitor for suspicious activity
    let suspiciousActivity = 0;
    
    // Monitor for rapid-fire events (potential bot activity)
    let eventCount = 0;
    const eventWindow = 1000; // 1 second
    
    document.addEventListener('click', function() {
        eventCount++;
        setTimeout(() => eventCount--, eventWindow);
        
        if (eventCount > 20) { // More than 20 clicks per second
            suspiciousActivity++;
            console.warn('Suspicious click activity detected');
        }
    });
    
    // Clear sensitive data on page unload
    window.addEventListener('beforeunload', function() {
        // Clear sensitive session data
        Security.session.clear();
        
        // Clear any sensitive form data
        const sensitiveInputs = document.querySelectorAll('input[type="password"], input[name*="key"]');
        sensitiveInputs.forEach(input => {
            input.value = '';
        });
    });
});

// Export for module usage
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { Security, SecureEventHandler };
}
