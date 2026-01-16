const express = require('express');
const session = require('express-session');
const path = require('path');
const fs = require('fs');
const http = require('http');
const socketIo = require('socket.io');
const bcrypt = require('bcryptjs');
const moment = require('moment');
const schedule = require('node-schedule');
const TelegramBot = require('node-telegram-bot-api');
require('dotenv').config();

// Database
const db = require('./database');

// WhatsApp Bot
const WhatsAppBot = require('./bot');

// Initialize Express
const app = express();
const server = http.createServer(app);
const io = socketIo(server);

// WhatsApp Bot instance
const whatsappBot = new WhatsAppBot();

// Telegram Bot
let telegramBot = null;
if (process.env.TELEGRAM_BOT_TOKEN) {
    telegramBot = new TelegramBot(process.env.TELEGRAM_BOT_TOKEN, { polling: true });
    console.log('🤖 Telegram bot initialized');
}

// Maintenance middleware
const checkMaintenance = async (req, res, next) => {
    try {
        const maintenance = db.getActiveMaintenance();
        if (maintenance && !req.path.includes('/api/login') && !req.path.includes('/login.html')) {
            if (req.session.userId) {
                const user = db.getUserById(req.session.userId);
                if (user && user.status === 'admin') {
                    return next(); // Admins can bypass maintenance
                }
            }
            
            // Show maintenance page
            const maintenanceEnd = moment(maintenance.end_time).fromNow();
            return res.status(503).send(`
                <!DOCTYPE html>
                <html lang="en">
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>Maintenance Mode - WhatsApp Bot</title>
                    <style>
                        * {
                            margin: 0;
                            padding: 0;
                            box-sizing: border-box;
                        }
                        
                        body {
                            font-family: 'Arial', sans-serif;
                            background: linear-gradient(45deg, #0a0a0a, #1a1a2e);
                            color: white;
                            min-height: 100vh;
                            display: flex;
                            justify-content: center;
                            align-items: center;
                            padding: 20px;
                        }
                        
                        .maintenance-container {
                            text-align: center;
                            padding: 40px;
                            background: rgba(255, 255, 255, 0.05);
                            backdrop-filter: blur(10px);
                            border-radius: 20px;
                            border: 1px solid rgba(255, 255, 255, 0.1);
                            max-width: 600px;
                            width: 100%;
                        }
                        
                        .maintenance-icon {
                            font-size: 80px;
                            color: #ffa500;
                            margin-bottom: 20px;
                            animation: pulse 2s infinite;
                        }
                        
                        @keyframes pulse {
                            0% { transform: scale(1); }
                            50% { transform: scale(1.1); }
                            100% { transform: scale(1); }
                        }
                        
                        h1 {
                            color: #ffa500;
                            margin-bottom: 20px;
                            font-size: 32px;
                        }
                        
                        p {
                            color: #aaa;
                            margin-bottom: 10px;
                            font-size: 18px;
                            line-height: 1.6;
                        }
                        
                        .countdown {
                            font-size: 24px;
                            color: #00b4db;
                            margin: 30px 0;
                            font-weight: bold;
                        }
                        
                        .reason {
                            background: rgba(255, 165, 0, 0.1);
                            padding: 15px;
                            border-radius: 10px;
                            margin: 20px 0;
                            border: 1px solid rgba(255, 165, 0, 0.3);
                        }
                        
                        .admin-note {
                            color: #00ff00;
                            font-size: 14px;
                            margin-top: 20px;
                        }
                        
                        a {
                            color: #00b4db;
                            text-decoration: none;
                        }
                        
                        a:hover {
                            text-decoration: underline;
                        }
                    </style>
                </head>
                <body>
                    <div class="maintenance-container">
                        <div class="maintenance-icon">🔧</div>
                        <h1>Under Maintenance</h1>
                        <p>We're currently performing scheduled maintenance to improve our service.</p>
                        
                        <div class="countdown" id="countdown">
                            Expected to be back ${maintenanceEnd}
                        </div>
                        
                        <div class="reason">
                            <strong>Reason:</strong> ${maintenance.reason || 'System upgrade and optimization'}
                        </div>
                        
                        <p>Thank you for your patience.</p>
                        
                        <div class="admin-note" id="adminNote"></div>
                    </div>
                    
                    <script>
                        // Update countdown
                        function updateCountdown() {
                            const countdown = document.getElementById('countdown');
                            const endTime = new Date('${maintenance.end_time}');
                            const now = new Date();
                            const diff = endTime - now;
                            
                            if (diff <= 0) {
                                countdown.textContent = 'Maintenance complete! Refreshing...';
                                setTimeout(() => location.reload(), 3000);
                                return;
                            }
                            
                            const hours = Math.floor(diff / (1000 * 60 * 60));
                            const minutes = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60));
                            const seconds = Math.floor((diff % (1000 * 60)) / 1000);
                            
                            countdown.textContent = \`Back in \${hours}h \${minutes}m \${seconds}s\`;
                        }
                        
                        setInterval(updateCountdown, 1000);
                        updateCountdown();
                    </script>
                </body>
                </html>
            `);
        }
        next();
    } catch (error) {
        console.error('Maintenance check error:', error);
        next();
    }
};

// Apply maintenance check to all routes except static files
app.use(checkMaintenance);

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Session middleware
app.use(session({
    secret: process.env.SESSION_SECRET || 'your-secret-key-change-this',
    resave: false,
    saveUninitialized: false,
    cookie: { 
        secure: process.env.NODE_ENV === 'production',
        maxAge: 24 * 60 * 60 * 1000 // 24 hours
    }
}));

// Authentication middleware
const requireAuth = (req, res, next) => {
    if (req.session && req.session.userId) {
        db.updateLastLogin(req.session.userId);
        return next();
    }
    res.redirect('/login.html');
};

// Admin middleware
const requireAdmin = (req, res, next) => {
    if (req.session && req.session.userId) {
        const user = db.getUserById(req.session.userId);
        if (user && user.status === 'admin') {
            return next();
        }
    }
    res.status(403).json({ error: 'Admin access required' });
};

// Global variable for template
app.use((req, res, next) => {
    res.locals.user = req.session.user;
    next();
});

// Routes
app.get('/', (req, res) => {
    if (req.session.userId) {
        res.redirect('/index.html');
    } else {
        res.redirect('/login.html');
    }
});

// Bypass maintenance for admins
app.get('/api/bypass-maintenance', requireAuth, (req, res) => {
    const user = db.getUserById(req.session.userId);
    if (user && user.status === 'admin') {
        req.session.bypassMaintenance = true;
        res.json({ success: true });
    } else {
        res.status(403).json({ error: 'Access denied' });
    }
});

// API Routes - Authentication
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    
    try {
        const user = db.getUserByUsername(username);
        
        if (user && bcrypt.compareSync(password, user.password)) {
            req.session.userId = user.id;
            req.session.user = {
                id: user.id,
                username: user.username,
                email: user.email,
                full_name: user.full_name,
                status: user.status,
                plan: user.plan
            };
            
            // Add audit log
            db.addAuditLog(user.id, 'LOGIN', 'User logged in', req.ip, req.headers['user-agent']);
            
            db.updateLastLogin(user.id);
            
            res.json({ 
                success: true, 
                user: req.session.user 
            });
        } else {
            res.json({ 
                success: false, 
                message: 'Invalid username or password' 
            });
        }
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Internal server error' 
        });
    }
});

app.get('/api/logout', (req, res) => {
    if (req.session.userId) {
        db.addAuditLog(req.session.userId, 'LOGOUT', 'User logged out', req.ip, req.headers['user-agent']);
    }
    req.session.destroy();
    res.redirect('/login.html');
});

// API Routes - User Profile
app.get('/api/user-profile', requireAuth, async (req, res) => {
    try {
        const userId = req.session.userId;
        const user = db.getUserById(userId);
        
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        // Get user statistics
        const stats = db.getUserStatistics(userId);
        
        // Get user bots
        const bots = db.getUserBots(userId);
        
        // Get subscription
        const subscription = db.getUserSubscription(userId);
        
        // Calculate days until expiry
        const expiryDate = new Date(user.subscription_expiry || user.created_at);
        const daysUntilExpiry = Math.ceil((expiryDate - new Date()) / (1000 * 60 * 60 * 24));
        
        const profileData = {
            username: user.username,
            fullName: user.full_name || user.username,
            email: user.email || `${user.username}@whatsappbot.com`,
            phone: user.phone || 'Not set',
            joinedDate: moment(user.created_at).format('MMMM YYYY'),
            userId: `USR-${user.id.toString().padStart(6, '0')}`,
            status: user.status,
            plan: user.plan,
            expirationDate: moment(expiryDate).format('YYYY-MM-DD'),
            daysUntilExpiry: daysUntilExpiry > 0 ? daysUntilExpiry : 0,
            apiKey: user.api_key,
            totalBots: stats?.total_bots || 0,
            activeBots: stats?.active_bots || 0,
            totalMessages: stats?.total_messages || 0,
            currentPlan: subscription?.plan_name || user.plan,
            planPrice: subscription?.price ? `$${subscription.price}` : 'Free',
            nextBilling: subscription?.end_date ? moment(subscription.end_date).format('YYYY-MM-DD') : 'N/A',
            autoRenew: subscription?.auto_renew ? 'Enabled' : 'Disabled',
            subscriptionStatus: subscription?.status || 'inactive',
            role: user.status,
            lastLogin: user.last_login ? moment(user.last_login).fromNow() : 'Never',
            bots: bots
        };
        
        res.json(profileData);
    } catch (error) {
        console.error('Profile error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/api/update-profile', requireAuth, (req, res) => {
    try {
        const userId = req.session.userId;
        const { fullName, email, phone } = req.body;
        
        const result = db.updateUser(userId, {
            full_name: fullName,
            email: email,
            phone: phone
        });
        
        if (result.changes > 0) {
            // Update session
            req.session.user.full_name = fullName;
            req.session.user.email = email;
            
            // Add audit log
            db.addAuditLog(userId, 'UPDATE_PROFILE', 'User updated profile', req.ip, req.headers['user-agent']);
            
            res.json({ 
                success: true, 
                message: 'Profile updated successfully' 
            });
        } else {
            res.json({ 
                success: false, 
                message: 'Failed to update profile' 
            });
        }
    } catch (error) {
        console.error('Update profile error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Internal server error' 
        });
    }
});

// API Routes - Admin Management
app.get('/api/admin/users', requireAdmin, (req, res) => {
    try {
        const users = db.getAllUsers();
        res.json(users);
    } catch (error) {
        console.error('Get users error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/api/admin/create-user', requireAdmin, (req, res) => {
    try {
        const { username, password, email, full_name, phone, status, plan, expired } = req.body;
        const createdBy = req.session.userId;
        
        // Check if user exists
        const existingUser = db.getUserByUsername(username);
        if (existingUser) {
            return res.json({ success: false, message: 'Username already exists' });
        }
        
        // Validate status
        const validStatuses = db.getAllStatuses().map(s => s.name);
        if (!validStatuses.includes(status)) {
            return res.json({ success: false, message: 'Invalid status' });
        }
        
        // Validate plan
        const validPlans = db.getAllPlans().map(p => p.name);
        if (!validPlans.includes(plan)) {
            return res.json({ success: false, message: 'Invalid plan' });
        }
        
        const userId = db.createUser({
            username,
            password,
            email,
            full_name,
            phone,
            status,
            plan,
            expired,
            created_by: createdBy
        });
        
        // Add audit log
        db.addAuditLog(createdBy, 'CREATE_USER', `Created user: ${username}`, req.ip, req.headers['user-agent']);
        
        res.json({ 
            success: true, 
            message: 'User created successfully',
            userId: userId
        });
    } catch (error) {
        console.error('Create user error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Internal server error' 
        });
    }
});

app.post('/api/admin/delete-user', requireAdmin, (req, res) => {
    try {
        const { userId } = req.body;
        const deletedBy = req.session.userId;
        
        // Get user info for audit log
        const user = db.getUserById(userId);
        if (!user) {
            return res.json({ success: false, message: 'User not found' });
        }
        
        // Don't allow deleting yourself
        if (userId == deletedBy) {
            return res.json({ success: false, message: 'Cannot delete yourself' });
        }
        
        const result = db.deleteUser(userId);
        
        if (result.changes > 0) {
            // Add audit log
            db.addAuditLog(deletedBy, 'DELETE_USER', `Deleted user: ${user.username}`, req.ip, req.headers['user-agent']);
            
            res.json({ 
                success: true, 
                message: 'User deleted successfully' 
            });
        } else {
            res.json({ 
                success: false, 
                message: 'Failed to delete user' 
            });
        }
    } catch (error) {
        console.error('Delete user error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Internal server error' 
        });
    }
});

// API Routes - Maintenance
app.get('/api/maintenance/status', (req, res) => {
    try {
        const maintenance = db.getActiveMaintenance();
        res.json({ 
            maintenance: maintenance,
            isMaintenance: !!maintenance
        });
    } catch (error) {
        console.error('Maintenance status error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.get('/api/admin/maintenance', requireAdmin, (req, res) => {
    try {
        const maintenance = db.getAllMaintenance();
        res.json(maintenance);
    } catch (error) {
        console.error('Get maintenance error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/api/admin/maintenance', requireAdmin, (req, res) => {
    try {
        const { date, action, reason } = req.body;
        const createdBy = req.session.userId;
        
        if (action === 'on') {
            // Parse date (accept hours or days)
            let endTime;
            if (date.includes('h')) {
                const hours = parseInt(date);
                endTime = new Date(Date.now() + hours * 60 * 60 * 1000);
            } else if (date.includes('d')) {
                const days = parseInt(date);
                endTime = new Date(Date.now() + days * 24 * 60 * 60 * 1000);
            } else if (date.includes('m')) {
                const minutes = parseInt(date);
                endTime = new Date(Date.now() + minutes * 60 * 1000);
            } else {
                // Assume hours
                const hours = parseInt(date);
                endTime = new Date(Date.now() + hours * 60 * 60 * 1000);
            }
            
            // Schedule auto-end
            scheduleMaintenanceEnd(endTime);
            
            const result = db.createMaintenance({
                start_time: new Date().toISOString(),
                end_time: endTime.toISOString(),
                reason: reason || 'Scheduled maintenance',
                created_by: createdBy
            });
            
            // Add audit log
            db.addAuditLog(createdBy, 'MAINTENANCE_ON', 
                `Maintenance scheduled until ${endTime.toISOString()}`, 
                req.ip, req.headers['user-agent']);
            
            res.json({ 
                success: true, 
                message: 'Maintenance mode activated',
                endTime: endTime.toISOString()
            });
        } else if (action === 'off') {
            // End all active maintenance
            const activeMaintenance = db.getActiveMaintenance();
            if (activeMaintenance) {
                db.endMaintenance(activeMaintenance.id);
                
                // Add audit log
                db.addAuditLog(createdBy, 'MAINTENANCE_OFF', 
                    'Maintenance mode ended manually', 
                    req.ip, req.headers['user-agent']);
                
                res.json({ 
                    success: true, 
                    message: 'Maintenance mode deactivated' 
                });
            } else {
                res.json({ 
                    success: false, 
                    message: 'No active maintenance found' 
                });
            }
        } else {
            res.json({ 
                success: false, 
                message: 'Invalid action. Use "on" or "off"' 
            });
        }
    } catch (error) {
        console.error('Maintenance error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Internal server error' 
        });
    }
});

// API Routes - Plans & Statuses
app.get('/api/plans', (req, res) => {
    try {
        const plans = db.getAllPlans();
        res.json(plans);
    } catch (error) {
        console.error('Get plans error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.get('/api/statuses', (req, res) => {
    try {
        const statuses = db.getAllStatuses();
        res.json(statuses);
    } catch (error) {
        console.error('Get statuses error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// API Routes - Dashboard
app.get('/api/dashboard-data', requireAuth, (req, res) => {
    try {
        const userId = req.session.userId;
        const user = db.getUserById(userId);
        const stats = db.getUserStatistics(userId);
        const bots = db.getUserBots(userId);
        const subscription = db.getUserSubscription(userId);
        const maintenance = db.getActiveMaintenance();
        
        // Calculate expiry
        const expiryDate = new Date(user.subscription_expiry || user.created_at);
        const daysUntilExpiry = Math.ceil((expiryDate - new Date()) / (1000 * 60 * 60 * 24));
        
        const dashboardData = {
            user: {
                username: user.username,
                fullName: user.full_name || user.username,
                status: user.status,
                plan: user.plan
            },
            expiry: {
                date: moment(expiryDate).format('YYYY-MM-DD'),
                days: daysUntilExpiry > 0 ? daysUntilExpiry : 0,
                status: daysUntilExpiry > 7 ? 'active' : daysUntilExpiry > 0 ? 'warning' : 'expired'
            },
            server: {
                status: 'active',
                uptime: process.uptime(),
                memory: process.memoryUsage(),
                cpu: process.cpuUsage(),
                maintenance: !!maintenance
            },
            statistics: {
                totalMessages: stats?.total_messages || 0,
                activeBots: stats?.active_bots || 0,
                totalBots: stats?.total_bots || 0,
                successRate: 95
            },
            bots: bots,
            supportTeam: [
                { name: 'Admin Support', contact: '@admin_support' },
                { name: 'Technical Support', contact: '@tech_support' },
                { name: 'Billing Support', contact: '@billing_support' }
            ]
        };
        
        res.json(dashboardData);
    } catch (error) {
        console.error('Dashboard data error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// API Routes - Bot Management
app.post('/api/bot/connect', requireAuth, (req, res) => {
    try {
        const userId = req.session.userId;
        const { phoneNumber } = req.body;
        
        // Check maintenance
        const maintenance = db.getActiveMaintenance();
        if (maintenance) {
            const user = db.getUserById(userId);
            if (user.status !== 'admin') {
                return res.json({ 
                    success: false, 
                    message: 'Cannot connect bot during maintenance' 
                });
            }
        }
        
        // Create bot record
        const result = db.createBot(userId, phoneNumber);
        
        // Generate pairing code
        const pairingCode = whatsappBot.generatePairingCode(phoneNumber);
        
        // Add audit log
        db.addAuditLog(userId, 'BOT_CONNECT', 
            `Initiated bot connection for ${phoneNumber}`, 
            req.ip, req.headers['user-agent']);
        
        res.json({
            success: true,
            botId: result.lastInsertRowid,
            pairingCode: pairingCode,
            message: 'Bot connection initiated'
        });
    } catch (error) {
        console.error('Bot connect error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Internal server error' 
        });
    }
});

// Function to schedule maintenance end
function scheduleMaintenanceEnd(endTime) {
    const job = schedule.scheduleJob(endTime, function() {
        console.log('Maintenance auto-ended at', new Date());
        // The maintenance will auto-end based on time check
    });
    console.log('Maintenance auto-end scheduled for', endTime);
}

// Telegram Bot Commands
if (telegramBot) {
    // Command handler
    telegramBot.onText(/\/start/, (msg) => {
        const chatId = msg.chat.id;
        const username = msg.from.username || msg.from.first_name;
        
        telegramBot.sendMessage(chatId, `🤖 *WhatsApp Bot Control Panel*\n\nWelcome ${username}!\n\n*Available commands:*\n\n📝 Create User:\n\`/create <username> <password> <expired> <plan> <status>\`\n\n🗑️ Delete User:\n\`/delete <username>\`\n\n🔧 Maintenance:\n\`/maintenance <time> <on/off> <reason>\`\n\n📋 Lists:\n\`/listusers\` - List all users\n\`/listplans\` - List available plans\n\`/liststatus\` - List available statuses\n\n*Example:*\n\`/create john123 password123 30d Premium user\`\n\`/maintenance 2h on "System upgrade"\`\n\n*Time format:* 30m (minutes), 2h (hours), 1d (days)`, {
            parse_mode: 'Markdown'
        });
    });
    
    // Create user command
    telegramBot.onText(/\/create (.+)/, async (msg, match) => {
        const chatId = msg.chat.id;
        const fromId = msg.from.id;
        
        // Check if user is admin in our system
        const adminUser = db.getUserByUsername(msg.from.username || `tg_${fromId}`);
        if (!adminUser || adminUser.status !== 'admin') {
            return telegramBot.sendMessage(chatId, '❌ *Access Denied*\n\nOnly admins can create users.', { parse_mode: 'Markdown' });
        }
        
        const args = match[1].split(' ');
        if (args.length < 5) {
            return telegramBot.sendMessage(chatId, '❌ *Usage:*\n\`/create <username> <password> <expired> <plan> <status>\`\n\n*Example:*\n\`/create john123 password123 30d Premium user\`\n\n*Available plans:* Basic, Premium, Vip, Verified, Admin, Developer, Hacker, Reseller\n*Available statuses:* user, dev, admin', { parse_mode: 'Markdown' });
        }
        
        const [username, password, expired, plan, status] = args;
        
        // Validate plan
        const validPlans = db.getAllPlans().map(p => p.name);
        if (!validPlans.includes(plan)) {
            return telegramBot.sendMessage(chatId, `❌ *Invalid plan*\n\nAvailable: ${validPlans.join(', ')}`, { parse_mode: 'Markdown' });
        }
        
        // Validate status
        const validStatuses = db.getAllStatuses().map(s => s.name);
        if (!validStatuses.includes(status)) {
            return telegramBot.sendMessage(chatId, `❌ *Invalid status*\n\nAvailable: ${validStatuses.join(', ')}`, { parse_mode: 'Markdown' });
        }
        
        try {
            // Check if user exists
            const existingUser = db.getUserByUsername(username);
            if (existingUser) {
                return telegramBot.sendMessage(chatId, '❌ *Username already exists*', { parse_mode: 'Markdown' });
            }
            
            // Create user
            const userId = db.createUser({
                username,
                password,
                plan,
                status,
                expired,
                created_by: adminUser.id
            });
            
            // Add audit log
            db.addAuditLog(adminUser.id, 'TG_CREATE_USER', 
                `Created user via Telegram: ${username}`, 
                'telegram', 'telegram-bot');
            
            telegramBot.sendMessage(chatId, `✅ *User Created Successfully!*\n\n👤 *Username:* ${username}\n🔐 *Password:* ${password}\n📅 *Expires:* ${expired}\n⭐ *Plan:* ${plan}\n👑 *Status:* ${status}\n🆔 *User ID:* ${userId}`, { parse_mode: 'Markdown' });
            
        } catch (error) {
            console.error('Telegram create error:', error);
            telegramBot.sendMessage(chatId, '❌ *Error creating user*', { parse_mode: 'Markdown' });
        }
    });
    
    // Delete user command
    telegramBot.onText(/\/delete (.+)/, async (msg, match) => {
        const chatId = msg.chat.id;
        
        // Check if user is admin
        const adminUser = db.getUserByUsername(msg.from.username || `tg_${msg.from.id}`);
        if (!adminUser || adminUser.status !== 'admin') {
            return telegramBot.sendMessage(chatId, '❌ *Access Denied*\n\nOnly admins can delete users.', { parse_mode: 'Markdown' });
        }
        
        const username = match[1].trim();
        
        try {
            // Get user
            const user = db.getUserByUsername(username);
            if (!user) {
                return telegramBot.sendMessage(chatId, '❌ *User not found*', { parse_mode: 'Markdown' });
            }
            
            // Don't allow deleting yourself
            if (user.id === adminUser.id) {
                return telegramBot.sendMessage(chatId, '❌ *Cannot delete yourself*', { parse_mode: 'Markdown' });
            }
            
            // Delete user
            db.deleteUser(user.id);
            
            // Add audit log
            db.addAuditLog(adminUser.id, 'TG_DELETE_USER', 
                `Deleted user via Telegram: ${username}`, 
                'telegram', 'telegram-bot');
            
            telegramBot.sendMessage(chatId, `✅ *User Deleted Successfully!*\n\n👤 *Username:* ${username}\n🗑️ *Status:* Deleted`, { parse_mode: 'Markdown' });
            
        } catch (error) {
            console.error('Telegram delete error:', error);
            telegramBot.sendMessage(chatId, '❌ *Error deleting user*', { parse_mode: 'Markdown' });
        }
    });
    
    // Maintenance command
    telegramBot.onText(/\/maintenance (.+)/, async (msg, match) => {
        const chatId = msg.chat.id;
        
        // Check if user is admin
        const adminUser = db.getUserByUsername(msg.from.username || `tg_${msg.from.id}`);
        if (!adminUser || adminUser.status !== 'admin') {
            return telegramBot.sendMessage(chatId, '❌ *Access Denied*\n\nOnly admins can manage maintenance.', { parse_mode: 'Markdown' });
        }
        
        const args = match[1].split(' ');
        if (args.length < 2) {
            return telegramBot.sendMessage(chatId, '❌ *Usage:*\n\`/maintenance <time> <on/off> <reason>\`\n\n*Example:*\n\`/maintenance 2h on "System upgrade"\`\n\`/maintenance 30m on "Emergency fix"\`\n\`/maintenance 0 off\`\n\n*Time format:* 30m (minutes), 2h (hours), 1d (days)', { parse_mode: 'Markdown' });
        }
        
        const [date, action] = args;
        const reason = args.slice(2).join(' ') || 'Scheduled maintenance';
        
        if (!['on', 'off'].includes(action.toLowerCase())) {
            return telegramBot.sendMessage(chatId, '❌ *Invalid action*\n\nUse "on" or "off"', { parse_mode: 'Markdown' });
        }
        
        try {
            if (action === 'on') {
                // Parse date
                let endTime;
                if (date.includes('h')) {
                    const hours = parseInt(date);
                    endTime = new Date(Date.now() + hours * 60 * 60 * 1000);
                } else if (date.includes('d')) {
                    const days = parseInt(date);
                    endTime = new Date(Date.now() + days * 24 * 60 * 60 * 1000);
                } else if (date.includes('m')) {
                    const minutes = parseInt(date);
                    endTime = new Date(Date.now() + minutes * 60 * 1000);
                } else {
                    return telegramBot.sendMessage(chatId, '❌ *Invalid time format*\n\nUse 30m, 2h, 1d', { parse_mode: 'Markdown' });
                }
                
                // Schedule maintenance
                scheduleMaintenanceEnd(endTime);
                
                const result = db.createMaintenance({
                    start_time: new Date().toISOString(),
                    end_time: endTime.toISOString(),
                    reason: reason,
                    created_by: adminUser.id
                });
                
                // Add audit log
                db.addAuditLog(adminUser.id, 'TG_MAINTENANCE_ON', 
                    `Maintenance via Telegram until ${endTime.toISOString()}`, 
                    'telegram', 'telegram-bot');
                
                const endTimeStr = moment(endTime).format('YYYY-MM-DD HH:mm:ss');
                telegramBot.sendMessage(chatId, `✅ *Maintenance Mode Activated!*\n\n⏰ *Ends at:* ${endTimeStr}\n📝 *Reason:* ${reason}\n\n⚠️ Website will be unavailable for non-admin users.`, { parse_mode: 'Markdown' });
                
            } else if (action === 'off') {
                // End maintenance
                const activeMaintenance = db.getActiveMaintenance();
                if (activeMaintenance) {
                    db.endMaintenance(activeMaintenance.id);
                    
                    // Add audit log
                    db.addAuditLog(adminUser.id, 'TG_MAINTENANCE_OFF', 
                        'Maintenance ended via Telegram', 
                        'telegram', 'telegram-bot');
                    
                    telegramBot.sendMessage(chatId, '✅ *Maintenance Mode Deactivated!*\n\n🌐 Website is now accessible to all users.', { parse_mode: 'Markdown' });
                } else {
                    telegramBot.sendMessage(chatId, 'ℹ️ *No active maintenance found*', { parse_mode: 'Markdown' });
                }
            }
            
        } catch (error) {
            console.error('Telegram maintenance error:', error);
            telegramBot.sendMessage(chatId, '❌ *Error managing maintenance*', { parse_mode: 'Markdown' });
        }
    });
    
    // List users command
    telegramBot.onText(/\/listusers/, async (msg) => {
        const chatId = msg.chat.id;
        
        // Check if user is admin
        const adminUser = db.getUserByUsername(msg.from.username || `tg_${msg.from.id}`);
        if (!adminUser || adminUser.status !== 'admin') {
            return telegramBot.sendMessage(chatId, '❌ *Access Denied*\n\nOnly admins can list users.', { parse_mode: 'Markdown' });
        }
        
        try {
            const users = db.getAllUsers();
            
            if (users.length === 0) {
                return telegramBot.sendMessage(chatId, '📋 *No users found*', { parse_mode: 'Markdown' });
            }
            
            let message = '📋 *User List:*\n\n';
            users.forEach((user, index) => {
                const expiry = user.subscription_expiry ? 
                    moment(user.subscription_expiry).format('MM/DD') : 'N/A';
                const lastLogin = user.last_login ? 
                    moment(user.last_login).format('MM/DD HH:mm') : 'Never';
                
                message += `*${index + 1}. ${user.username}*\n`;
                message += `   👑 Status: ${user.status}\n`;
                message += `   ⭐ Plan: ${user.plan}\n`;
                message += `   📅 Expires: ${expiry}\n`;
                message += `   🔐 Last login: ${lastLogin}\n\n`;
            });
            
            telegramBot.sendMessage(chatId, message, { parse_mode: 'Markdown' });
            
        } catch (error) {
            console.error('Telegram list users error:', error);
            telegramBot.sendMessage(chatId, '❌ *Error listing users*', { parse_mode: 'Markdown' });
        }
    });
    
    // List plans command
    telegramBot.onText(/\/listplans/, async (msg) => {
        const chatId = msg.chat.id;
        
        try {
            const plans = db.getAllPlans();
            
            let message = '📋 *Available Plans:*\n\n';
            plans.forEach((plan, index) => {
                message += `*${index + 1}. ${plan.name}*\n`;
                message += `   💰 Price: $${plan.price}\n`;
                message += `   🤖 Max Bots: ${plan.max_bots}\n`;
                message += `   📨 Max Msgs/Day: ${plan.max_messages_per_day.toLocaleString()}\n`;
                message += `   ✨ Features: ${plan.features}\n\n`;
            });
            
            telegramBot.sendMessage(chatId, message, { parse_mode: 'Markdown' });
            
        } catch (error) {
            console.error('Telegram list plans error:', error);
            telegramBot.sendMessage(chatId, '❌ *Error listing plans*', { parse_mode: 'Markdown' });
        }
    });
    
    // List statuses command
    telegramBot.onText(/\/liststatus/, async (msg) => {
        const chatId = msg.chat.id;
        
        try {
            const statuses = db.getAllStatuses();
            
            let message = '📋 *Available Statuses:*\n\n';
            statuses.forEach((status, index) => {
                message += `*${index + 1}. ${status.name}*\n`;
                message += `   📊 Level: ${status.level}\n`;
                message += `   🔑 Permissions: ${status.permissions}\n\n`;
            });
            
            telegramBot.sendMessage(chatId, message, { parse_mode: 'Markdown' });
            
        } catch (error) {
            console.error('Telegram list statuses error:', error);
            telegramBot.sendMessage(chatId, '❌ *Error listing statuses*', { parse_mode: 'Markdown' });
        }
    });
}

// WebSocket connection
io.on('connection', (socket) => {
    console.log('New client connected');
    
    // Send connection count to all clients
    const clientsCount = io.engine.clientsCount;
    io.emit('connection-count', { count: clientsCount });
    
    // Send maintenance status
    const maintenance = db.getActiveMaintenance();
    socket.emit('maintenance-status', { 
        maintenance: !!maintenance,
        endTime: maintenance?.end_time 
    });
    
    socket.on('connect-bot', async (data) => {
        const { phoneNumber, userId } = data;
        
        // Check maintenance
        const maintenance = db.getActiveMaintenance();
        if (maintenance) {
            const user = db.getUserById(userId);
            if (user.status !== 'admin') {
                socket.emit('connection-error', {
                    message: 'Cannot connect bot during maintenance'
                });
                return;
            }
        }
        
        try {
            // Generate pairing code
            const pairingCode = whatsappBot.generatePairingCode(phoneNumber);
            
            // Emit pairing code to client
            socket.emit('pairing-code', { 
                code: pairingCode,
                phoneNumber: phoneNumber
            });
            
            // Connect WhatsApp bot
            const result = await whatsappBot.connect(phoneNumber, userId);
            
            if (result.success) {
                setTimeout(() => {
                    socket.emit('connection-status', { 
                        connected: true,
                        phoneNumber: phoneNumber,
                        message: 'Connected successfully'
                    });
                }, 3000);
            } else {
                socket.emit('connection-error', {
                    message: result.message
                });
            }
            
        } catch (error) {
            console.error('WebSocket bot connect error:', error);
            socket.emit('connection-error', {
                message: 'Internal server error'
            });
        }
    });
    
    socket.on('disconnect', () => {
        console.log('Client disconnected');
        const clientsCount = io.engine.clientsCount;
        io.emit('connection-count', { count: clientsCount });
    });
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).send('Something broke!');
});

// Start server
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`
    ╔══════════════════════════════════════════════════╗
    ║           WhatsApp Bot Web Dashboard             ║
    ╠══════════════════════════════════════════════════╣
    ║ Server running on port ${PORT}                         ║
    ║ Access: http://localhost:${PORT}                         ║
    ║ Telegram Bot: ${telegramBot ? '✅ Active' : '❌ Not configured'}          ║
    ║                                                  ║
    ║ Features:                                        ║
    ║ • WhatsApp Bot Management                        ║
    ║ • Telegram Admin Commands                        ║
    ║ • Maintenance Mode                               ║
    ║ • User Management                                ║
    ║ • Real-time Statistics                           ║
    ╚══════════════════════════════════════════════════╝
    
    Telegram Commands:
    /create <username> <password> <expired> <plan> <status>
    /delete <username>
    /maintenance <time> <on/off> <reason>
    /listusers /listplans /liststatus
    
    Example:
    /create john123 password123 30d Premium user
    /maintenance 2h on "System upgrade"
    `);
});
