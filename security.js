
import os

output_dir = '/mnt/agents/output/nova-space'

# 2. security.js
security_js = """/**
 * Nova Space Security Module
 * XSS Prevention, SQL Injection Detection, Rate Limiting, CSRF Protection
 */

const Security = {
    // XSS Prevention - escape all HTML entities
    escapeHtml(text) {
        if (!text) return '';
        const div = document.createElement('div');
        div.textContent = String(text);
        return div.innerHTML;
    },

    // SQL Injection Detection Patterns
    sqlPatterns: [
        /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER|CREATE|EXEC|EXECUTE|TRUNCATE|REPLACE|MERGE|GRANT|REVOKE)\b)/i,
        /(--|\/\*|\*\/|;)/,
        /(\bOR\b|\bAND\b)\s+\d+\s*=\s*\d+/i,
        /'\s*OR\s*'/i,
        /;\s*DROP\s+/i,
        /xp_/i,
        /sp_/i,
        /WAITFOR\s+DELAY/i,
        /BULK\s+INSERT/i,
        /INTO\s+OUTFILE/i,
        /LOAD_FILE/i,
        /SLEEP\s*\(/i,
        /PG_SLEEP/i,
        /DBMS_PIPE/i
    ],

    detectSQLInjection(input) {
        if (typeof input !== 'string') return false;
        return this.sqlPatterns.some(pattern => pattern.test(input));
    },

    sanitizeSQL(input) {
        if (typeof input !== 'string') return '';
        return input
            .replace(/[;\-\-\/\*\*\/]/g, '')
            .replace(/(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER|CREATE|EXEC|EXECUTE|TRUNCATE)\b)/gi, '')
            .replace(/'/g, "''")
            .trim();
    },

    isValidEmail(email) {
        const re = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$/;
        return re.test(email);
    },

    // Rate Limiter
    rateLimiter: new Map(),
    
    checkRateLimit(key, maxRequests = 10, windowMs = 60000) {
        const now = Date.now();
        const windowStart = now - windowMs;
        
        if (!this.rateLimiter.has(key)) {
            this.rateLimiter.set(key, []);
        }
        
        const requests = this.rateLimiter.get(key).filter(t => t > windowStart);
        
        if (requests.length >= maxRequests) {
            return false;
        }
        
        requests.push(now);
        this.rateLimiter.set(key, requests);
        return true;
    },

    // CSRF Token
    generateCSRFToken() {
        const array = new Uint8Array(32);
        crypto.getRandomValues(array);
        return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
    },

    // XSS Pattern Detection
    xssPatterns: [
        /<script\\b[^<]*(?:(?!<\\/script>)<[^<]*)*<\\/script>/gi,
        /javascript:/gi,
        /on\\w+\\s*=/gi,
        /<iframe/gi,
        /<object/gi,
        /<embed/gi,
        /<form/gi,
        /data:text\\/html/gi,
        /expression\\s*\\(/gi
    ],

    detectXSS(input) {
        if (typeof input !== 'string') return false;
        return this.xssPatterns.some(pattern => pattern.test(input));
    },

    // Main Input Validation
    validateInput(input, type = 'text', maxLength = 1000) {
        if (!input || typeof input !== 'string') {
            return { valid: false, error: 'Invalid input' };
        }
        
        if (input.length > maxLength) {
            return { valid: false, error: `Input too long (max ${maxLength} chars)` };
        }
        
        if (type === 'email' && !this.isValidEmail(input)) {
            return { valid: false, error: 'Invalid email format' };
        }
        
        if (this.detectSQLInjection(input)) {
            console.warn('SQL Injection detected:', input.substring(0, 50));
            return { valid: false, error: 'Potential SQL injection detected - request blocked' };
        }
        
        if (this.detectXSS(input)) {
            console.warn('XSS detected:', input.substring(0, 50));
            return { valid: false, error: 'Potential XSS attack detected - request blocked' };
        }
        
        // Sanitize output
        const sanitized = this.escapeHtml(input);
        
        return { valid: true, sanitized };
    },

    // Password Strength Check
    checkPasswordStrength(password) {
        const checks = {
            length: password.length >= 8,
            uppercase: /[A-Z]/.test(password),
            lowercase: /[a-z]/.test(password),
            number: /\\d/.test(password),
            special: /[!@#$%^&*()_+\\-=\\[\\]{};':"\\|,.<>\\/?]/.test(password)
        };
        
        const score = Object.values(checks).filter(Boolean).length;
        
        let strength = 'weak';
        if (score >= 5) strength = 'strong';
        else if (score >= 3) strength = 'medium';
        
        return { score, strength, checks };
    },

    // Hash string (simple, for client-side only)
    async hashString(str) {
        const encoder = new TextEncoder();
        const data = encoder.encode(str);
        const hashBuffer = await crypto.subtle.digest('SHA-256', data);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    }
};

// Export for module usage
if (typeof module !== 'undefined' && module.exports) {
    module.exports = Security;
}
"""

with open(os.path.join(output_dir, 'security.js'), 'w', encoding='utf-8') as f:
    f.write(security_js)

print("✅ security.js created")
print(f"Size: {len(security_js)} bytes")
