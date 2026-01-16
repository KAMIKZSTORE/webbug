const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

class DatabaseManager {
    constructor() {
        this.db = new Database('database.db');
        this.init();
    }

    init() {
        // Enable foreign keys
        this.db.pragma('foreign_keys = ON');
    }

    // User methods
    getUserByUsername(username) {
        const stmt = this.db.prepare(`
            SELECT u.*, s.theme, s.notifications, s.two_factor
            FROM users u
            LEFT JOIN user_settings s ON u.id = s.user_id
            WHERE u.username = ? AND u.is_active = 1
        `);
        return stmt.get(username);
    }

    getUserById(id) {
        const stmt = this.db.prepare(`
            SELECT u.*, s.theme, s.notifications, s.two_factor
            FROM users u
            LEFT JOIN user_settings s ON u.id = s.user_id
            WHERE u.id = ? AND u.is_active = 1
        `);
        return stmt.get(id);
    }

    getAllUsers() {
        const stmt = this.db.prepare(`
            SELECT id, username, email, status, plan, 
                   subscription_expiry, created_at, last_login
            FROM users 
            WHERE is_active = 1
            ORDER BY created_at DESC
        `);
        return stmt.all();
    }

    createUser(userData) {
        const { username, password, email, full_name, phone, status, plan, expired, created_by } = userData;
        
        // Hash password if provided
        const hashedPassword = password ? bcrypt.hashSync(password, 10) : bcrypt.hashSync('default123', 10);
        
        // Calculate expiry date
        let expiryDate;
        if (expired) {
            const timeMatch = expired.match(/(\d+)([dhm])/);
            if (timeMatch) {
                const value = parseInt(timeMatch[1]);
                const unit = timeMatch[2];
                let multiplier = 24 * 60 * 60 * 1000; // default days
                
                if (unit === 'h') multiplier = 60 * 60 * 1000;
                else if (unit === 'm') multiplier = 60 * 1000;
                
                expiryDate = new Date(Date.now() + value * multiplier);
            } else {
                // Assume days if no unit specified
                expiryDate = new Date(Date.now() + parseInt(expired) * 24 * 60 * 60 * 1000);
            }
        } else {
            expiryDate = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000); // Default 30 days
        }
        
        const apiKey = 'sk_live_' + crypto.randomBytes(16).toString('hex');
        
        const insertUser = this.db.prepare(`
            INSERT INTO users (username, password, email, full_name, phone, status, plan, api_key, subscription_expiry, created_by)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `);
        
        const info = insertUser.run(
            username, 
            hashedPassword, 
            email || `${username}@whatsappbot.com`, 
            full_name || username,
            phone || '',
            status || 'user',
            plan || 'Basic',
            apiKey,
            expiryDate.toISOString(),
            created_by || null
        );
        
        // Create settings for user
        const insertSettings = this.db.prepare(`
            INSERT INTO user_settings (user_id) VALUES (?)
        `);
        insertSettings.run(info.lastInsertRowid);
        
        // Create initial statistics
        const insertStats = this.db.prepare(`
            INSERT INTO statistics (user_id) VALUES (?)
        `);
        insertStats.run(info.lastInsertRowid);
        
        // Create subscription
        const planData = this.getPlan(plan || 'Basic');
        const insertSub = this.db.prepare(`
            INSERT INTO subscriptions (user_id, plan_name, price, start_date, end_date)
            VALUES (?, ?, ?, ?, ?)
        `);
        insertSub.run(
            info.lastInsertRowid,
            plan || 'Basic',
            planData?.price || 0,
            new Date().toISOString(),
            expiryDate.toISOString()
        );
        
        return info.lastInsertRowid;
    }

    updateUser(userId, userData) {
        const { email, full_name, phone, status, plan } = userData;
        
        const stmt = this.db.prepare(`
            UPDATE users 
            SET email = ?, full_name = ?, phone = ?, status = ?, plan = ?
            WHERE id = ?
        `);
        
        return stmt.run(email, full_name, phone, status, plan, userId);
    }

    deleteUser(userId, deletedBy) {
        // Soft delete - set is_active to 0
        const stmt = this.db.prepare('UPDATE users SET is_active = 0 WHERE id = ?');
        return stmt.run(userId);
    }

    updatePassword(userId, newPassword) {
        const hashedPassword = bcrypt.hashSync(newPassword, 10);
        const stmt = this.db.prepare('UPDATE users SET password = ? WHERE id = ?');
        return stmt.run(hashedPassword, userId);
    }

    regenerateApiKey(userId) {
        const newApiKey = 'sk_live_' + crypto.randomBytes(16).toString('hex');
        const stmt = this.db.prepare('UPDATE users SET api_key = ? WHERE id = ?');
        stmt.run(newApiKey, userId);
        return newApiKey;
    }

    // Plan methods
    getPlan(planName) {
        const stmt = this.db.prepare('SELECT * FROM plans WHERE name = ? AND is_active = 1');
        return stmt.get(planName);
    }

    getAllPlans() {
        const stmt = this.db.prepare('SELECT * FROM plans WHERE is_active = 1 ORDER BY price ASC');
        return stmt.all();
    }

    // Status methods
    getStatus(statusName) {
        const stmt = this.db.prepare('SELECT * FROM statuses WHERE name = ? AND is_active = 1');
        return stmt.get(statusName);
    }

    getAllStatuses() {
        const stmt = this.db.prepare('SELECT * FROM statuses WHERE is_active = 1 ORDER BY level ASC');
        return stmt.all();
    }

    // Maintenance methods
    getActiveMaintenance() {
        const stmt = this.db.prepare(`
            SELECT * FROM maintenance 
            WHERE is_active = 1 
            AND datetime(end_time) > datetime('now')
            ORDER BY end_time DESC
            LIMIT 1
        `);
        return stmt.get();
    }

    getAllMaintenance() {
        const stmt = this.db.prepare(`
            SELECT m.*, u.username as created_by_name
            FROM maintenance m
            LEFT JOIN users u ON m.created_by = u.id
            ORDER BY m.created_at DESC
        `);
        return stmt.all();
    }

    createMaintenance(data) {
        const { start_time, end_time, reason, created_by } = data;
        
        const stmt = this.db.prepare(`
            INSERT INTO maintenance (start_time, end_time, reason, created_by)
            VALUES (?, ?, ?, ?)
        `);
        
        return stmt.run(start_time, end_time, reason, created_by);
    }

    endMaintenance(maintenanceId) {
        const stmt = this.db.prepare(`
            UPDATE maintenance 
            SET is_active = 0 
            WHERE id = ?
        `);
        return stmt.run(maintenanceId);
    }

    // Bot methods
    getUserBots(userId) {
        const stmt = this.db.prepare(`
            SELECT * FROM bots 
            WHERE user_id = ? 
            ORDER BY created_at DESC
        `);
        return stmt.all(userId);
    }

    createBot(userId, phoneNumber) {
        const stmt = this.db.prepare(`
            INSERT INTO bots (user_id, phone_number, status)
            VALUES (?, ?, 'inactive')
        `);
        return stmt.run(userId, phoneNumber);
    }

    updateBotStatus(botId, status) {
        const stmt = this.db.prepare(`
            UPDATE bots 
            SET status = ?, last_active = CURRENT_TIMESTAMP
            WHERE id = ?
        `);
        return stmt.run(status, botId);
    }

    // Statistics methods
    getUserStatistics(userId) {
        const stmt = this.db.prepare(`
            SELECT 
                SUM(messages_sent) as total_messages,
                COUNT(DISTINCT b.id) as total_bots,
                SUM(CASE WHEN b.status = 'active' THEN 1 ELSE 0 END) as active_bots
            FROM users u
            LEFT JOIN statistics s ON u.id = s.user_id
            LEFT JOIN bots b ON u.id = b.user_id
            WHERE u.id = ?
            GROUP BY u.id
        `);
        return stmt.get(userId);
    }

    incrementMessagesSent(userId, count = 1) {
        const stmt = this.db.prepare(`
            INSERT INTO statistics (user_id, messages_sent, date)
            VALUES (?, ?, CURRENT_DATE)
            ON CONFLICT(user_id, date) DO UPDATE SET
            messages_sent = messages_sent + ?
        `);
        return stmt.run(userId, count, count);
    }

    // Subscription methods
    getUserSubscription(userId) {
        const stmt = this.db.prepare(`
            SELECT * FROM subscriptions 
            WHERE user_id = ? AND status = 'active'
            ORDER BY end_date DESC
            LIMIT 1
        `);
        return stmt.get(userId);
    }

    // Audit log methods
    addAuditLog(userId, action, details, ip, userAgent) {
        const stmt = this.db.prepare(`
            INSERT INTO audit_log (user_id, action, details, ip_address, user_agent)
            VALUES (?, ?, ?, ?, ?)
        `);
        return stmt.run(userId, action, details, ip, userAgent);
    }

    getAuditLogs(limit = 100) {
        const stmt = this.db.prepare(`
            SELECT a.*, u.username 
            FROM audit_log a
            LEFT JOIN users u ON a.user_id = u.id
            ORDER BY a.created_at DESC
            LIMIT ?
        `);
        return stmt.all(limit);
    }

    // Update user last login
    updateLastLogin(userId) {
        const stmt = this.db.prepare('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?');
        return stmt.run(userId);
    }

    // Check if user is admin
    isAdmin(userId) {
        const user = this.getUserById(userId);
        return user && user.status === 'admin';
    }

    // Check user permissions
    hasPermission(userId, requiredLevel) {
        const user = this.getUserById(userId);
        if (!user) return false;
        
        const status = this.getStatus(user.status);
        return status && status.level >= requiredLevel;
    }

    // Close database
    close() {
        this.db.close();
    }
}

module.exports = new DatabaseManager();
