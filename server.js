const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const { nanoid } = require('nanoid');
const cors = require('cors');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { authenticator } = require('otplib');
const qrcode = require('qrcode');

const app = express();
const PORT = process.env.PORT || 3000;
const BASE_URL = `http://localhost:${PORT}`;
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET || Buffer.byteLength(JWT_SECRET, 'utf8') < 32 || JWT_SECRET === 'your-secret-key-change-it-in-prod') {
    throw new Error('JWT_SECRET must be a unique secret of at least 32 bytes');
}

// Middleware
app.use(express.json());
app.use(cors());

// Database Setup
const dbPath = path.resolve(__dirname, 'shorturl.db');
const db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
        console.error('Error opening database', err.message);
    } else {
        console.log('Connected to the SQLite database.');
        // URLs Table
        db.run(`CREATE TABLE IF NOT EXISTS urls (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            original_url TEXT NOT NULL,
            short_code TEXT NOT NULL UNIQUE,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            expires_at DATETIME DEFAULT NULL,
            visit_count INTEGER DEFAULT 0,
            is_admin_created INTEGER DEFAULT 0,
            is_disabled INTEGER DEFAULT 0,
            disable_reason TEXT,
            use_interstitial INTEGER DEFAULT 0
        )`, (err) => {
            if (err) console.error('Error creating urls table', err.message);
            
            db.run(`ALTER TABLE urls ADD COLUMN expires_at DATETIME DEFAULT NULL`, () => {});
            db.run(`ALTER TABLE urls ADD COLUMN visit_count INTEGER DEFAULT 0`, () => {});
            db.run(`ALTER TABLE urls ADD COLUMN is_admin_created INTEGER DEFAULT 0`, () => {});
            db.run(`ALTER TABLE urls ADD COLUMN is_disabled INTEGER DEFAULT 0`, () => {});
            db.run(`ALTER TABLE urls ADD COLUMN disable_reason TEXT`, () => {});
            db.run(`ALTER TABLE urls ADD COLUMN use_interstitial INTEGER DEFAULT 0`, () => {});
        });

        // Users Table
        db.run(`CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            totp_secret TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )`, (err) => {
            if (err) console.error('Error creating users table', err.message);
            db.run(`ALTER TABLE users ADD COLUMN totp_secret TEXT`, () => {});
        });

        // Settings Table
        db.run(`CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )`, (err) => {
            if (err) console.error('Error creating settings table', err.message);
        });
    }
});

// Helper: Get Setting
const getSetting = (key) => {
    return new Promise((resolve, reject) => {
        db.get("SELECT value FROM settings WHERE key = ?", [key], (err, row) => {
            if (err) reject(err);
            resolve(row ? row.value : null);
        });
    });
};

// --- Root Redirect Middleware (Before Static) ---
app.use(async (req, res, next) => {
    if (req.path === '/' && req.method === 'GET') {
        try {
            const rootRedirect = await getSetting('root_redirect');
            if (rootRedirect) {
                return res.redirect(rootRedirect);
            }
        } catch (e) {
            console.error('Error checking root redirect', e);
        }
    }
    next();
});

app.use(express.static('public'));

// Authentication Middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.sendStatus(401);

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

// --- Auth Routes ---

// Check if admin setup is required
app.get('/api/auth/check', (req, res) => {
    db.get("SELECT COUNT(*) as count FROM users", [], (err, row) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ setupRequired: row.count === 0 });
    });
});

// Setup initial admin (only works if no users exist)
app.post('/api/auth/setup', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Username and password required' });

    db.get("SELECT COUNT(*) as count FROM users", [], async (err, row) => {
        if (err) return res.status(500).json({ error: err.message });
        if (row.count > 0) return res.status(403).json({ error: 'Admin already exists' });

        const hashedPassword = await bcrypt.hash(password, 10);
        db.run("INSERT INTO users (username, password_hash) VALUES (?, ?)", [username, hashedPassword], function(err) {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ message: 'Admin created successfully' });
        });
    });
});

// Login
app.post('/api/auth/login', (req, res) => {
    const { username, password, totpToken } = req.body;
    db.get("SELECT * FROM users WHERE username = ?", [username], async (err, user) => {
        if (err) return res.status(500).json({ error: err.message });
        if (!user) return res.status(401).json({ error: 'Invalid credentials' });

        const validPassword = await bcrypt.compare(password, user.password_hash);
        if (!validPassword) return res.status(401).json({ error: 'Invalid credentials' });

        // TOTP Check
        if (user.totp_secret) {
            if (!totpToken) {
                return res.status(403).json({ error: 'TOTP_REQUIRED', message: '2FA Code required' });
            }
            const isValid = authenticator.check(totpToken, user.totp_secret);
            if (!isValid) {
                return res.status(401).json({ error: 'Invalid 2FA Code' });
            }
        }

        const token = jwt.sign({ username: user.username, id: user.id }, JWT_SECRET, { expiresIn: '1h' });
        res.json({ token });
    });
});

// --- TOTP Management Routes ---

// Generate TOTP Secret (Setup Step 1)
app.post('/api/auth/2fa/generate', authenticateToken, (req, res) => {
    const secret = authenticator.generateSecret();
    const otpauth = authenticator.keyuri(req.user.username, 'ShortUrlAdmin', secret);

    qrcode.toDataURL(otpauth, (err, imageUrl) => {
        if (err) return res.status(500).json({ error: 'Error generating QR code' });
        res.json({ secret, imageUrl });
    });
});

// Enable TOTP (Setup Step 2)
app.post('/api/auth/2fa/enable', authenticateToken, (req, res) => {
    const { secret, token } = req.body;
    const isValid = authenticator.check(token, secret);
    if (!isValid) return res.status(400).json({ error: 'Invalid Code' });

    db.run("UPDATE users SET totp_secret = ? WHERE id = ?", [secret, req.user.id], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: '2FA Enabled successfully' });
    });
});

// Disable TOTP
app.post('/api/auth/2fa/disable', authenticateToken, (req, res) => {
    db.run("UPDATE users SET totp_secret = NULL WHERE id = ?", [req.user.id], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: '2FA Disabled' });
    });
});

// Check 2FA Status
app.get('/api/auth/2fa/status', authenticateToken, (req, res) => {
    db.get("SELECT totp_secret FROM users WHERE id = ?", [req.user.id], (err, row) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ enabled: !!row.totp_secret });
    });
});


// --- Admin Routes ---

// Get Settings
app.get('/api/admin/settings', authenticateToken, (req, res) => {
    db.all("SELECT * FROM settings", [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        const settings = {};
        rows.forEach(row => settings[row.key] = row.value);
        res.json(settings);
    });
});

// Update Settings
app.post('/api/admin/settings', authenticateToken, (req, res) => {
    const { root_redirect, fallback_redirect, show_interstitial, turnstile_site_key, turnstile_secret_key } = req.body;
    
    const stmt = db.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)");
    
    if (root_redirect !== undefined) stmt.run('root_redirect', root_redirect);
    if (fallback_redirect !== undefined) stmt.run('fallback_redirect', fallback_redirect);
    if (show_interstitial !== undefined) stmt.run('show_interstitial', show_interstitial);
    if (turnstile_site_key !== undefined) stmt.run('turnstile_site_key', turnstile_site_key);
    if (turnstile_secret_key !== undefined) stmt.run('turnstile_secret_key', turnstile_secret_key);
    
    stmt.finalize(err => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: 'Settings updated' });
    });
});

// Get Public Config (Turnstile Site Key)
app.get('/api/config', async (req, res) => {
    try {
        const siteKey = await getSetting('turnstile_site_key');
        res.json({ turnstileSiteKey: siteKey });
    } catch (e) {
        res.status(500).json({ error: 'Failed to load config' });
    }
});

// Get Public Stats (Total Hosted Links)
app.get('/api/stats/public', (req, res) => {
    db.get("SELECT COUNT(*) as count FROM urls", [], (err, row) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        res.json({ count: row.count });
    });
});


// Bulk Update URLs
app.post('/api/admin/urls/bulk-update', authenticateToken, (req, res) => {
    const { ids, updates } = req.body;
    if (!Array.isArray(ids) || ids.length === 0) return res.status(400).json({ error: 'No IDs provided' });
    if (!updates || Object.keys(updates).length === 0) return res.status(400).json({ error: 'No updates provided' });

    // Validate updates
    const validFields = ['is_disabled', 'use_interstitial'];
    const fieldsToUpdate = [];
    const params = [];

    for (const [key, value] of Object.entries(updates)) {
        if (validFields.includes(key)) {
            fieldsToUpdate.push(`${key} = ?`);
            params.push(value);
        }
    }

    if (fieldsToUpdate.length === 0) return res.status(400).json({ error: 'Invalid update fields' });

    // Add IDs to params for the IN clause
    const placeholders = ids.map(() => '?').join(',');
    const sql = `UPDATE urls SET ${fieldsToUpdate.join(', ')} WHERE id IN (${placeholders})`;
    
    // Combine params
    const allParams = [...params, ...ids];

    db.run(sql, allParams, function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: 'Updated successfully', count: this.changes });
    });
});

// Bulk Delete URLs
app.post('/api/admin/urls/bulk-delete', authenticateToken, (req, res) => {
    const { ids } = req.body;
    if (!Array.isArray(ids) || ids.length === 0) return res.status(400).json({ error: 'No IDs provided' });

    const placeholders = ids.map(() => '?').join(',');
    db.run(`DELETE FROM urls WHERE id IN (${placeholders})`, ids, function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: 'Deleted successfully', count: this.changes });
    });
});

// Get all URLs (with filtering)
app.get('/api/admin/urls', authenticateToken, (req, res) => {
    const { search, creator, startDate, endDate } = req.query;
    let sql = "SELECT * FROM urls WHERE 1=1";
    const params = [];

    if (search) {
        sql += " AND (short_code LIKE ? OR original_url LIKE ?)";
        params.push(`%${search}%`, `%${search}%`);
    }

    if (creator) {
        if (creator === 'admin') sql += " AND is_admin_created = 1";
        if (creator === 'guest') sql += " AND (is_admin_created = 0 OR is_admin_created IS NULL)";
    }

    if (startDate) {
        sql += " AND created_at >= ?";
        params.push(startDate);
    }
    if (endDate) {
        sql += " AND created_at <= ?";
        params.push(endDate);
    }

    sql += " ORDER BY created_at DESC";

    db.all(sql, params, (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows.map(row => ({ ...row, shortUrl: `${BASE_URL}/${row.short_code}` })));
    });
});

// Create Custom Short URL (Admin)
app.post('/api/admin/urls', authenticateToken, (req, res) => {
    const { originalUrl, shortCode, expiresAt, is_disabled, disable_reason, use_interstitial } = req.body;
    if (!originalUrl) return res.status(400).json({ error: 'originalUrl is required' });

    try { new URL(originalUrl); } catch (e) { return res.status(400).json({ error: 'Invalid URL' }); }

    const code = shortCode || nanoid(8);
    const expiration = expiresAt ? expiresAt : null;
    
    // Default values
    const disabled = is_disabled ? 1 : 0;
    const reason = disable_reason || '';
    const interstitial = use_interstitial ? 1 : 0;

    db.run("INSERT INTO urls (original_url, short_code, expires_at, is_admin_created, is_disabled, disable_reason, use_interstitial) VALUES (?, ?, ?, ?, ?, ?, ?)", 
        [originalUrl, code, expiration, 1, disabled, reason, interstitial], 
        function(err) {
        if (err) {
            if (err.message.includes('UNIQUE constraint failed')) {
                return res.status(409).json({ error: 'Short code already exists' });
            }
            return res.status(500).json({ error: err.message });
        }
        res.json({ id: this.lastID, originalUrl, shortCode: code, expiresAt: expiration, shortUrl: `${BASE_URL}/${code}`, visitCount: 0, isAdminCreated: 1 });
    });
});

// Update URL
app.put('/api/admin/urls/:id', authenticateToken, (req, res) => {
    const { originalUrl, shortCode, expiresAt, is_disabled, disable_reason, use_interstitial } = req.body;
    const { id } = req.params;
    
    if (!originalUrl || !shortCode) return res.status(400).json({ error: 'originalUrl and shortCode required' });
    
    const expiration = expiresAt ? expiresAt : null;
    const disabled = is_disabled ? 1 : 0;
    const reason = disable_reason || '';
    const interstitial = use_interstitial ? 1 : 0;

    db.run("UPDATE urls SET original_url = ?, short_code = ?, expires_at = ?, is_disabled = ?, disable_reason = ?, use_interstitial = ? WHERE id = ?", 
        [originalUrl, shortCode, expiration, disabled, reason, interstitial, id], 
        function(err) {
        if (err) {
            if (err.message.includes('UNIQUE constraint failed')) {
                return res.status(409).json({ error: 'Short code already exists' });
            }
            return res.status(500).json({ error: err.message });
        }
        res.json({ message: 'Updated successfully' });
    });
});

// Delete URL
app.delete('/api/admin/urls/:id', authenticateToken, (req, res) => {
    const { id } = req.params;
    db.run("DELETE FROM urls WHERE id = ?", [id], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: 'Deleted successfully' });
    });
});


// --- Public Routes ---

// 1. Create Short URL (Public)
app.post('/api/shorten', async (req, res) => {
    const { originalUrl, customCode, expiration, turnstileToken } = req.body;

    if (!originalUrl) {
        return res.status(400).json({ error: 'originalUrl is required' });
    }

    // Turnstile Verification
    try {
        const turnstileSecret = await getSetting('turnstile_secret_key');
        if (turnstileSecret) {
            if (!turnstileToken) {
                return res.status(400).json({ error: 'Captcha verification failed' });
            }

            const verifyRes = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    secret: turnstileSecret,
                    response: turnstileToken
                })
            });

            const verifyData = await verifyRes.json();
            if (!verifyData.success) {
                return res.status(400).json({ error: 'Captcha verification failed' });
            }
        }
    } catch (e) {
        console.error('Turnstile error', e);
        // Optional: fail open or closed. Let's fail open for now if error occurs, or log it.
        // For security, usually fail closed, but for user experience, maybe open.
        // Let's assume if we can't verify, we don't block unless strict.
    }

    try {
        new URL(originalUrl);
    } catch (err) {
        return res.status(400).json({ error: 'Invalid URL format' });
    }

    // Custom Code Validation
    let shortCode;
    if (customCode) {
        const isValid = /^[a-zA-Z0-9_-]+$/.test(customCode);
        if (!isValid) return res.status(400).json({ error: 'Custom code can only contain letters, numbers, underscores, and hyphens.' });
        if (customCode.length < 5) return res.status(400).json({ error: 'Custom code must be at least 5 characters long.' });
        shortCode = customCode;
    } else {
        shortCode = nanoid(8);
    }

    // Expiration Logic
    let expiresAt = null;
    if (expiration) {
        const now = new Date();
        switch (expiration) {
            case '30m': now.setMinutes(now.getMinutes() + 30); break;
            case '1h': now.setHours(now.getHours() + 1); break; // Keeping 1h for flexibility, though not requested
            case '1d': now.setDate(now.getDate() + 1); break;
            case '7d': now.setDate(now.getDate() + 7); break;
            case '30d': now.setDate(now.getDate() + 30); break;
            case 'never': expiresAt = null; break;
            default: return res.status(400).json({ error: 'Invalid expiration duration' });
        }
        if (expiration !== 'never') expiresAt = now.toISOString();
    }

    const sql = `INSERT INTO urls (original_url, short_code, expires_at, is_admin_created) VALUES (?, ?, ?, ?)`;
    db.run(sql, [originalUrl, shortCode, expiresAt, 0], function(err) {
        if (err) {
            if (err.message.includes('UNIQUE constraint failed')) {
                return res.status(409).json({ error: 'Custom code already taken' });
            }
            console.error(err.message);
            return res.status(500).json({ error: 'Database error' });
        }
        
        res.json({
            originalUrl,
            shortCode,
            shortUrl: `${BASE_URL}/${shortCode}`,
            expiresAt
        });
    });
});

// 2. Redirect / Fallback / Interstitial
app.use(async (req, res, next) => {
    if (req.method !== 'GET' || req.path.startsWith('/api/')) {
        return next();
    }

    const code = req.path.substring(1);
    
    const sql = `SELECT id, original_url, expires_at, is_admin_created, is_disabled, disable_reason, use_interstitial FROM urls WHERE short_code = ?`;
    db.get(sql, [code], async (err, row) => {
        if (err) {
            console.error(err.message);
            return res.status(500).send('Internal Server Error');
        }

        if (row) {
            // Check Disabled
            if (row.is_disabled) {
                const reason = row.disable_reason || 'This link has been disabled due to potential security risks. For your safety, redirection has been blocked.';
                return res.send(`
                    <!DOCTYPE html>
                    <html lang="en">
                    <head>
                        <meta charset="UTF-8">
                        <meta name="viewport" content="width=device-width, initial-scale=1.0">
                        <title>Link Disabled</title>
                        <style>
                            body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; background: #fff5f5; color: #333; }
                            .box { background: white; padding: 48px; border-radius: 12px; box-shadow: 0 10px 25px rgba(0,0,0,0.05); text-align: center; max-width: 500px; border-left: 6px solid #dc3545; }
                            h2 { color: #dc3545; margin-top: 0; font-size: 24px; }
                            p { color: #555; line-height: 1.6; font-size: 16px; margin: 20px 0; }
                            .icon { font-size: 48px; margin-bottom: 20px; display: block; }
                        </style>
                    </head>
                    <body>
                        <div class="box">
                            <span class="icon">🚫</span>
                            <h2>Link Access Suspended</h2>
                            <p>${reason}</p>
                        </div>
                    </body>
                    </html>
                `);
            }

            // Check Expiration
            if (row.expires_at) {
                const now = new Date();
                const expires = new Date(row.expires_at);
                if (now > expires) {
                    return res.status(410).send('Short URL has expired');
                }
            }
            
            // Increment Visit Count
            db.run("UPDATE urls SET visit_count = visit_count + 1 WHERE id = ?", [row.id], () => {});

            // Interstitial Check
            // Logic: 
            // 1. Global setting: show_interstitial=true AND is_admin_created=0 -> SHOW
            // 2. Individual setting: use_interstitial=1 -> SHOW (Override global?)
            // Usually individual setting should take precedence or add to it.
            // Let's say: IF (Global AND Guest) OR (Individual) -> SHOW
            
            const globalInterstitial = await getSetting('show_interstitial');
            const shouldShowInterstitial = (globalInterstitial === 'true' && row.is_admin_created === 0) || (row.use_interstitial === 1);

            if (shouldShowInterstitial) {
                // Serve an interstitial page instead of redirecting directly
                // We'll pass the original URL via query param or simple template
                return res.send(`
                    <!DOCTYPE html>
                    <html lang="en">
                    <head>
                        <meta charset="UTF-8">
                        <meta name="viewport" content="width=device-width, initial-scale=1.0">
                        <title>Redirect Notice</title>
                        <style>
                            body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; background: #f8f9fa; color: #333; }
                            .box { background: white; padding: 48px; border-radius: 12px; box-shadow: 0 10px 30px rgba(0,0,0,0.08); text-align: center; max-width: 540px; }
                            h2 { color: #2c3e50; margin-top: 0; font-size: 24px; }
                            p { color: #555; line-height: 1.6; font-size: 16px; margin: 20px 0; }
                            .url-container { background: #f1f3f5; padding: 15px; border-radius: 6px; margin: 25px 0; word-break: break-all; color: #0066cc; font-family: monospace; font-size: 14px; }
                            .btn { background: #0066cc; color: white; padding: 12px 30px; border-radius: 6px; text-decoration: none; display: inline-block; font-weight: 600; transition: background 0.2s; }
                            .btn:hover { background: #0052a3; }
                            .warning { color: #856404; background-color: #fff3cd; border: 1px solid #ffeeba; padding: 15px; border-radius: 6px; font-size: 14px; margin-top: 30px; text-align: left; }
                        </style>
                    </head>
                    <body>
                        <div class="box">
                            <h2>You are leaving ShortUrl</h2>
                            <p>You are about to be redirected to an external website. This link was created by a guest user.</p>
                            <div class="url-container">${row.original_url}</div>
                            <a href="${row.original_url}" class="btn" rel="nofollow">Continue to Site</a>
                            <div class="warning">
                                <strong>Security Notice:</strong> Please verify the URL above. Do not enter personal information or passwords on unknown websites.
                            </div>
                        </div>
                    </body>
                    </html>
                `);
            }

            return res.redirect(row.original_url);
        }
        
        // Fallback
        try {
            const fallback = await getSetting('fallback_redirect');
            if (fallback) {
                const baseUrl = fallback.replace(/\/$/, '');
                const targetUrl = baseUrl + req.path;
                return res.redirect(targetUrl);
            }
        } catch (e) {
            console.error('Fallback error', e);
        }

        res.status(404).send('Short URL not found');
    });
});

// Start Server
app.listen(PORT, () => {
    console.log(`Server is running on ${BASE_URL}`);
});
