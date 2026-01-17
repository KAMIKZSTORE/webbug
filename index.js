const express = require('express');
const session = require('express-session');
const path = require('path');
const fs = require('fs');
const http = require('http');
const socketIo = require('socket.io');
const bcrypt = require('bcryptjs');
const moment = require('moment');
const schedule = require('node-schedule');
const os = require('os');
require('dotenv').config();

// =============== ADMIN CONFIGURATION ===============
const ADMIN_ID = process.env.ADMIN_ID || '8443969542';
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin';

// =============== RAILWAY CONFIGURATION ===============
const PORT = process.env.PORT || 3000;
const NODE_ENV = process.env.NODE_ENV || 'production';
const SESSION_SECRET = process.env.SESSION_SECRET || 'railway-secret-key-change-in-production';
const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;

// =============== CREATE APP ===============
const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});

// =============== HEALTHCHECK FOR RAILWAY ===============
app.get('/health', (req, res) => {
    const stats = getServerStats();
    res.status(200).json({
        status: 'OK',
        timestamp: new Date().toISOString(),
        service: 'WhatsApp Bot Dashboard',
        uptime: process.uptime(),
        platform: 'Railway',
        adminId: ADMIN_ID,
        version: '1.0.0',
        serverStats: {
            memory: stats.memory?.usage || 'N/A',
            cpu: stats.cpu?.usage || 'N/A',
            uptime: stats.system?.uptime || 'N/A'
        }
    });
});

// =============== MIDDLEWARE CONFIGURATION ===============
app.set('trust proxy', 1);

const sessionConfig = {
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: NODE_ENV === 'production',
        sameSite: NODE_ENV === 'production' ? 'none' : 'lax',
        maxAge: 24 * 60 * 60 * 1000
    },
    store: new session.MemoryStore()
};

app.use(session(sessionConfig));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(express.static(__dirname));

// =============== DATABASE SETUP ===============
let db;
let dbType = 'mock';

try {
    if (fs.existsSync('./database.js')) {
        db = require('./database');
        console.log('✅ Loaded real database');
        dbType = 'real';
    } else if (fs.existsSync('./database.json')) {
        const rawData = fs.readFileSync('./database.json');
        db = JSON.parse(rawData);
        console.log('✅ Loaded JSON database');
        dbType = 'json';
    } else {
        throw new Error('Database file not found');
    }
} catch (error) {
    console.log('⚠️ Using mock database:', error.message);
    
    db = {
        getActiveMaintenance: () => null,
        getUserById: (id) => ({
            id: 1,
            username: ADMIN_USERNAME,
            email: 'admin@whatsappbot.com',
            full_name: 'Administrator',
            status: 'admin',
            plan: 'Premium',
            phone: 'Not set',
            subscription_expiry: new Date(Date.now() + 30*24*60*60*1000),
            created_at: new Date(),
            last_login: new Date(),
            api_key: 'sk_live_mock_' + Math.random().toString(36).substr(2, 20),
            telegram_id: ADMIN_ID
        }),
        getUserByUsername: (username) => {
            if (username === ADMIN_USERNAME) {
                return {
                    id: 1,
                    username: ADMIN_USERNAME,
                    password: bcrypt.hashSync(process.env.ADMIN_PASSWORD || 'admin123', 10),
                    email: 'admin@whatsappbot.com',
                    full_name: 'Administrator',
                    status: 'admin',
                    plan: 'Premium',
                    telegram_id: ADMIN_ID
                };
            }
            return null;
        },
        getUserByTelegramId: (telegramId) => {
            if (telegramId === ADMIN_ID) {
                return {
                    id: 1,
                    username: ADMIN_USERNAME,
                    password: bcrypt.hashSync(process.env.ADMIN_PASSWORD || 'admin123', 10),
                    email: 'admin@whatsappbot.com',
                    full_name: 'Administrator',
                    status: 'admin',
                    plan: 'Premium',
                    telegram_id: ADMIN_ID
                };
            }
            return null;
        },
        updateLastLogin: (id) => ({ changes: 1 }),
        getUserStatistics: (id) => ({
            total_bots: 2,
            active_bots: 1,
            total_messages: 1254
        }),
        getUserBots: (id) => [
            {
                id: 1,
                name: 'Main Bot',
                status: 'connected',
                phone_number: '+1234567890'
            },
            {
                id: 2,
                name: 'Backup Bot',
                status: 'inactive',
                phone_number: '+0987654321'
            }
        ],
        getUserSubscription: (id) => ({
            plan_name: 'Premium',
            price: 9.99,
            end_date: new Date(Date.now() + 30*24*60*60*1000),
            auto_renew: true,
            status: 'active'
        }),
        getAllPlans: () => [
            {
                name: 'Free',
                price: 0,
                max_bots: 1,
                max_messages_per_day: 100,
                features: 'Basic features'
            },
            {
                name: 'Premium',
                price: 9.99,
                max_bots: 5,
                max_messages_per_day: 1000,
                features: 'All features'
            },
            {
                name: 'VIP',
                price: 29.99,
                max_bots: 20,
                max_messages_per_day: 5000,
                features: 'VIP support'
            }
        ],
        getAllStatuses: () => [
            { name: 'user', level: 1, permissions: 'basic' },
            { name: 'admin', level: 10, permissions: 'full' }
        ],
        getAllUsers: () => [
            {
                id: 1,
                username: ADMIN_USERNAME,
                email: 'admin@whatsappbot.com',
                full_name: 'Administrator',
                status: 'admin',
                plan: 'Premium',
                subscription_expiry: new Date(Date.now() + 30*24*60*60*1000),
                last_login: new Date(),
                created_at: new Date(Date.now() - 7*24*60*60*1000),
                telegram_id: ADMIN_ID
            }
        ],
        updateUser: (id, data) => ({ changes: 1 }),
        createUser: (data) => ({ lastInsertRowid: 2 }),
        deleteUser: (id) => ({ changes: 1 }),
        addAuditLog: (userId, action, description, ip, userAgent) => true,
        getAllMaintenance: () => [],
        createMaintenance: (data) => ({ id: 1 }),
        endMaintenance: (id) => ({ changes: 1 }),
        createBot: (userId, phoneNumber) => ({ lastInsertRowid: 1 })
    };
}

// =============== SERVER STATISTICS FUNCTION ===============
function getServerStats() {
    try {
        const mem = process.memoryUsage();
        const cpus = os.cpus();
        const load = os.loadavg();
        const uptime = process.uptime();
        const totalMem = os.totalmem();
        const freeMem = os.freemem();
        const usedMem = totalMem - freeMem;
        
        let cpuUsage = '0.00';
        if (cpus && cpus.length > 0) {
            let totalIdle = 0, totalTick = 0;
            cpus.forEach((cpu) => {
                for (let type in cpu.times) {
                    totalTick += cpu.times[type];
                }
                totalIdle += cpu.times.idle;
            });
            cpuUsage = totalTick > 0 ? ((1 - totalIdle / totalTick) * 100).toFixed(2) : '0.00';
        }
        
        const formatBytes = (bytes) => {
            if (bytes === 0) return '0 Bytes';
            const k = 1024;
            const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        };
        
        const formatUptime = (seconds) => {
            const days = Math.floor(seconds / (3600 * 24));
            const hours = Math.floor((seconds % (3600 * 24)) / 3600);
            const minutes = Math.floor((seconds % 3600) / 60);
            const secs = Math.floor(seconds % 60);
            
            let result = '';
            if (days > 0) result += `${days}d `;
            if (hours > 0) result += `${hours}h `;
            if (minutes > 0) result += `${minutes}m `;
            if (secs > 0 || result === '') result += `${secs}s`;
            return result.trim();
        };
        
        return {
            cpu: {
                usage: cpuUsage + '%',
                cores: cpus ? cpus.length : 0,
                model: cpus && cpus[0] ? cpus[0].model : 'Unknown',
                load1: load[0] ? load[0].toFixed(2) : '0.00',
                load5: load[1] ? load[1].toFixed(2) : '0.00',
                load15: load[2] ? load[2].toFixed(2) : '0.00'
            },
            memory: {
                total: formatBytes(totalMem),
                used: formatBytes(usedMem),
                free: formatBytes(freeMem),
                usage: ((usedMem / totalMem) * 100).toFixed(2) + '%',
                heapTotal: formatBytes(mem.heapTotal),
                heapUsed: formatBytes(mem.heapUsed),
                rss: formatBytes(mem.rss)
            },
            system: {
                platform: os.platform(),
                arch: os.arch(),
                hostname: os.hostname(),
                uptime: formatUptime(uptime),
                osUptime: formatUptime(os.uptime()),
                nodeVersion: process.version,
                pid: process.pid
            },
            railway: {
                environment: NODE_ENV,
                port: PORT
            },
            timestamp: new Date().toISOString()
        };
    } catch (error) {
        console.error('Error getting server stats:', error);
        return { error: 'Failed to get server statistics' };
    }
}

// =============== TELEGRAM BOT SETUP ===============
let telegramBot = null;

async function sendMessageToAdmin(message) {
    if (!telegramBot) return false;
    
    try {
        await telegramBot.sendMessage(ADMIN_ID, message, { parse_mode: 'Markdown' });
        console.log(`✅ Message sent to admin ${ADMIN_ID}`);
        return true;
    } catch (error) {
        console.error('Error sending message to admin:', error.message);
        return false;
    }
}

function initializeTelegramBot() {
    if (!TELEGRAM_BOT_TOKEN) {
        console.log('ℹ️ Telegram bot token not configured, bot will be disabled');
        return;
    }
    
    try {
        const TelegramBot = require('node-telegram-bot-api');
        
        console.log('🤖 Initializing Telegram bot...');
        
        if (NODE_ENV === 'production') {
            const webhookUrl = process.env.RAILWAY_STATIC_URL || process.env.WEBHOOK_URL;
            if (webhookUrl) {
                telegramBot = new TelegramBot(TELEGRAM_BOT_TOKEN);
                telegramBot.setWebHook(`${webhookUrl}/bot${TELEGRAM_BOT_TOKEN}`);
                console.log(`✅ Telegram webhook set to: ${webhookUrl}/bot${TELEGRAM_BOT_TOKEN}`);
                
                app.post(`/bot${TELEGRAM_BOT_TOKEN}`, (req, res) => {
                    telegramBot.processUpdate(req.body);
                    res.sendStatus(200);
                });
            } else {
                console.log('⚠️ Using polling mode (no webhook URL configured)');
                telegramBot = new TelegramBot(TELEGRAM_BOT_TOKEN, { polling: true });
            }
        } else {
            telegramBot = new TelegramBot(TELEGRAM_BOT_TOKEN, { polling: true });
        }
        
        console.log('✅ Telegram bot initialized successfully');
        
        setupTelegramBotCommands();
        
    } catch (error) {
        console.error('❌ Telegram bot initialization error:', error.message);
        telegramBot = null;
    }
}

function setupTelegramBotCommands() {
    if (!telegramBot) return;
    
    telegramBot.onText(/\/start/, (msg) => {
        const chatId = msg.chat.id;
        const userId = msg.from.id;
        const username = msg.from.username || msg.from.first_name;
        const isAdmin = userId.toString() === ADMIN_ID;
        
        let welcomeMessage = `🤖 *WhatsApp Bot Control Panel*\n\n`;
        welcomeMessage += `Welcome ${username}!\n`;
        welcomeMessage += `🚂 *Hosted on:* Railway\n\n`;
        
        if (isAdmin) {
            welcomeMessage += `👑 *Status:* Administrator\n\n`;
            welcomeMessage += `*Available commands:*\n`;
            welcomeMessage += `/ping - Server statistics\n`;
            welcomeMessage += `/createuser - Create new user\n`;
            welcomeMessage += `/deleteuser - Delete user\n`;
            welcomeMessage += `/listusers - Show all users\n`;
            welcomeMessage += `/maintenance - Maintenance control\n`;
            welcomeMessage += `/broadcast - Send broadcast\n`;
            welcomeMessage += `/help - Show help message`;
        } else {
            welcomeMessage += `👤 *Status:* User\n\n`;
            welcomeMessage += `*Available commands:*\n`;
            welcomeMessage += `/ping - Check server status\n`;
            welcomeMessage += `/help - Show help message\n\n`;
            welcomeMessage += `*Contact admin:* @${ADMIN_USERNAME}`;
        }
        
        telegramBot.sendMessage(chatId, welcomeMessage, { parse_mode: 'Markdown' });
    });
    
    telegramBot.onText(/\/ping/, async (msg) => {
        const chatId = msg.chat.id;
        const userId = msg.from.id;
        const username = msg.from.username || msg.from.first_name;
        
        try {
            const stats = getServerStats();
            let message = `📊 *SERVER STATISTICS*\n\n`;
            message += `👤 *User:* ${username}\n`;
            message += `🚂 *Platform:* Railway\n`;
            message += `📅 *Timestamp:* ${moment().format('YYYY-MM-DD HH:mm:ss')}\n\n`;
            message += `⚙️ *CPU:* ${stats.cpu.usage}\n`;
            message += `💾 *Memory:* ${stats.memory.usage}\n`;
            message += `⏰ *Uptime:* ${stats.system.uptime}\n\n`;
            message += `✅ *Status:* ONLINE`;
            
            telegramBot.sendMessage(chatId, message, { parse_mode: 'Markdown' });
        } catch (error) {
            telegramBot.sendMessage(chatId, '❌ Error getting server statistics', { parse_mode: 'Markdown' });
        }
    });
    
    telegramBot.onText(/\/broadcast (.+)/, async (msg, match) => {
        const chatId = msg.chat.id;
        const userId = msg.from.id;
        
        if (userId.toString() !== ADMIN_ID) {
            return telegramBot.sendMessage(chatId, '❌ *Access Denied*', { parse_mode: 'Markdown' });
        }
        
        const message = match[1].trim();
        if (!message) {
            return telegramBot.sendMessage(chatId, '❌ *Usage:* /broadcast <message>', { parse_mode: 'Markdown' });
        }
        
        try {
            const users = db.getAllUsers();
            let successCount = 0;
            
            const broadcastMessage = `📢 *BROADCAST*\n\n${message}\n\n*From:* Admin\n*Time:* ${moment().format('HH:mm')}`;
            
            for (const user of users) {
                if (user.telegram_id && user.telegram_id !== ADMIN_ID) {
                    try {
                        await telegramBot.sendMessage(user.telegram_id, broadcastMessage, { parse_mode: 'Markdown' });
                        successCount++;
                    } catch (error) {
                        console.error(`Failed to send to ${user.username}:`, error.message);
                    }
                }
            }
            
            telegramBot.sendMessage(chatId, `✅ Broadcast sent to ${successCount} users`, { parse_mode: 'Markdown' });
        } catch (error) {
            console.error('Broadcast error:', error);
            telegramBot.sendMessage(chatId, '❌ Error sending broadcast', { parse_mode: 'Markdown' });
        }
    });
    
    telegramBot.onText(/\/createuser (.+)/, async (msg, match) => {
        const chatId = msg.chat.id;
        const userId = msg.from.id;
        
        if (userId.toString() !== ADMIN_ID) {
            return telegramBot.sendMessage(chatId, '❌ *Access Denied*', { parse_mode: 'Markdown' });
        }
        
        const args = match[1].split(' ');
        if (args.length < 5) {
            return telegramBot.sendMessage(chatId, '❌ *Usage:* /createuser <username> <password> <plan> <status> <days>', { parse_mode: 'Markdown' });
        }
        
        const [username, password, plan, status, days] = args;
        
        try {
            const existingUser = db.getUserByUsername(username);
            if (existingUser) {
                return telegramBot.sendMessage(chatId, '❌ Username already exists', { parse_mode: 'Markdown' });
            }
            
            const userIdResult = db.createUser({
                username,
                password: bcrypt.hashSync(password, 10),
                plan,
                status,
                expired: `${days}d`,
                created_by: 1,
                email: `${username}@whatsappbot.com`,
                full_name: username
            });
            
            telegramBot.sendMessage(chatId, `✅ User ${username} created successfully!`, { parse_mode: 'Markdown' });
        } catch (error) {
            console.error('Create user error:', error);
            telegramBot.sendMessage(chatId, '❌ Error creating user', { parse_mode: 'Markdown' });
        }
    });
    
    telegramBot.onText(/\/listusers/, async (msg) => {
        const chatId = msg.chat.id;
        const userId = msg.from.id;
        
        if (userId.toString() !== ADMIN_ID) {
            return telegramBot.sendMessage(chatId, '❌ *Access Denied*', { parse_mode: 'Markdown' });
        }
        
        try {
            const users = db.getAllUsers();
            if (users.length === 0) {
                return telegramBot.sendMessage(chatId, '📭 No users found', { parse_mode: 'Markdown' });
            }
            
            let message = `📋 *User List (${users.length}):*\n\n`;
            users.forEach((user, index) => {
                message += `${index + 1}. *${user.username}*\n`;
                message += `   Status: ${user.status}\n`;
                message += `   Plan: ${user.plan}\n`;
                message += `   ---\n`;
            });
            
            telegramBot.sendMessage(chatId, message, { parse_mode: 'Markdown' });
        } catch (error) {
            console.error('List users error:', error);
            telegramBot.sendMessage(chatId, '❌ Error listing users', { parse_mode: 'Markdown' });
        }
    });
    
    telegramBot.onText(/\/help/, (msg) => {
        const chatId = msg.chat.id;
        const userId = msg.from.id;
        const isAdmin = userId.toString() === ADMIN_ID;
        
        if (isAdmin) {
            telegramBot.sendMessage(chatId, 
                `🆘 *Admin Help*\n\n` +
                `*Commands:*\n` +
                `/start - Start bot\n` +
                `/ping - Server stats\n` +
                `/createuser - Create user\n` +
                `/deleteuser - Delete user\n` +
                `/listusers - List users\n` +
                `/broadcast - Send message\n` +
                `/maintenance - Maintenance\n` +
                `/help - This message`,
                { parse_mode: 'Markdown' }
            );
        } else {
            telegramBot.sendMessage(chatId,
                `🆘 *Help*\n\n` +
                `/start - Start bot\n` +
                `/ping - Server status\n` +
                `/help - This message\n\n` +
                `Contact @${ADMIN_USERNAME} for admin access.`,
                { parse_mode: 'Markdown' }
            );
        }
    });
    
    telegramBot.on('polling_error', (error) => {
        console.error('Telegram polling error:', error);
    });
    
    console.log('✅ Telegram bot commands registered');
}

// Initialize bot
initializeTelegramBot();

// =============== GLOBAL MIDDLEWARE ===============
app.use((req, res, next) => {
    res.locals.user = req.session.user;
    next();
});

// =============== MAINTENANCE MIDDLEWARE ===============
const checkMaintenance = async (req, res, next) => {
    try {
        if (req.path === '/health' || req.path.startsWith('/bot')) {
            return next();
        }
        
        const maintenance = db.getActiveMaintenance();
        if (maintenance && !req.path.includes('/api/login') && !req.path.includes('/login.html')) {
            if (req.session.userId) {
                const user = db.getUserById(req.session.userId);
                if (user && user.status === 'admin') {
                    return next();
                }
            }
            const maintenanceEnd = moment(maintenance.end_time).fromNow();
            return res.status(503).send(`
                <!DOCTYPE html>
                <html lang="en">
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>Maintenance Mode</title>
                    <style>
                        body { 
                            font-family: Arial, sans-serif; 
                            background: linear-gradient(45deg, #0a0a0a, #1a1a2e); 
                            color: white; 
                            min-height: 100vh; 
                            display: flex; 
                            justify-content: center; 
                            align-items: center; 
                            padding: 20px; 
                        }
                        .container { 
                            text-align: center; 
                            padding: 40px; 
                            background: rgba(255, 255, 255, 0.05); 
                            backdrop-filter: blur(10px); 
                            border-radius: 20px; 
                            border: 1px solid rgba(255, 255, 255, 0.1); 
                            max-width: 600px; 
                            width: 100%; 
                        }
                        .icon { 
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
                        h1 { color: #ffa500; margin-bottom: 20px; font-size: 32px; }
                        p { color: #aaa; margin-bottom: 10px; font-size: 18px; line-height: 1.6; }
                        .countdown { font-size: 24px; color: #00b4db; margin: 30px 0; font-weight: bold; }
                        .reason { 
                            background: rgba(255, 165, 0, 0.1); 
                            padding: 15px; 
                            border-radius: 10px; 
                            margin: 20px 0; 
                            border: 1px solid rgba(255, 165, 0, 0.3); 
                        }
                    </style>
                </head>
                <body>
                    <div class="container">
                        <div class="icon">🛠️</div>
                        <h1>Under Maintenance</h1>
                        <p>We're currently performing scheduled maintenance.</p>
                        <div class="countdown" id="countdown">Back ${maintenanceEnd}</div>
                        <div class="reason">
                            <strong>Reason:</strong> ${maintenance.reason || 'System upgrade'}
                        </div>
                        <p>Thank you for your patience.</p>
                    </div>
                    <script>
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

app.use(checkMaintenance);

// =============== AUTHENTICATION MIDDLEWARE ===============
const requireAuth = (req, res, next) => {
    if (req.session && req.session.userId) {
        db.updateLastLogin(req.session.userId);
        return next();
    }
    res.redirect('/login.html');
};

const requireAdmin = (req, res, next) => {
    if (req.session && req.session.userId) {
        const user = db.getUserById(req.session.userId);
        if (user && user.status === 'admin') {
            return next();
        }
    }
    res.status(403).json({ error: 'Admin access required' });
};

// =============== ROUTES ===============
app.get('/', (req, res) => {
    if (req.session.userId) {
        res.redirect('/index.html');
    } else {
        res.redirect('/login.html');
    }
});

app.get('/api/bypass-maintenance', requireAuth, (req, res) => {
    const user = db.getUserById(req.session.userId);
    if (user && user.status === 'admin') {
        req.session.bypassMaintenance = true;
        res.json({ success: true });
    } else {
        res.status(403).json({ error: 'Access denied' });
    }
});

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
            
            db.addAuditLog(user.id, 'LOGIN', 'User logged in', req.ip, req.headers['user-agent']);
            db.updateLastLogin(user.id);
            
            if (telegramBot && user.username !== ADMIN_USERNAME) {
                const loginMessage = 
                    `🔐 *User Login*\n\n` +
                    `*User:* ${user.username}\n` +
                    `*Time:* ${moment().format('HH:mm:ss')}\n` +
                    `*IP:* ${req.ip}`;
                
                sendMessageToAdmin(loginMessage);
            }
            
            res.json({ success: true, user: req.session.user });
        } else {
            res.json({ success: false, message: 'Invalid username or password' });
        }
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
});

app.get('/api/logout', (req, res) => {
    if (req.session.userId) {
        db.addAuditLog(req.session.userId, 'LOGOUT', 'User logged out', req.ip, req.headers['user-agent']);
    }
    req.session.destroy();
    res.redirect('/login.html');
});

app.get('/api/user-profile', requireAuth, async (req, res) => {
    try {
        const userId = req.session.userId;
        const user = db.getUserById(userId);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        const stats = db.getUserStatistics(userId);
        const bots = db.getUserBots(userId);
        const subscription = db.getUserSubscription(userId);
        
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
            req.session.user.full_name = fullName;
            req.session.user.email = email;
            
            db.addAuditLog(userId, 'UPDATE_PROFILE', 'User updated profile', req.ip, req.headers['user-agent']);
            res.json({ success: true, message: 'Profile updated successfully' });
        } else {
            res.json({ success: false, message: 'Failed to update profile' });
        }
    } catch (error) {
        console.error('Update profile error:', error);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
});

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
        
        const existingUser = db.getUserByUsername(username);
        if (existingUser) {
            return res.json({ success: false, message: 'Username already exists' });
        }
        
        const validStatuses = db.getAllStatuses().map(s => s.name);
        if (!validStatuses.includes(status)) {
            return res.json({ success: false, message: 'Invalid status' });
        }
        
        const validPlans = db.getAllPlans().map(p => p.name);
        if (!validPlans.includes(plan)) {
            return res.json({ success: false, message: 'Invalid plan' });
        }
        
        const userId = db.createUser({
            username,
            password: bcrypt.hashSync(password, 10),
            email,
            full_name,
            phone,
            status,
            plan,
            expired,
            created_by: createdBy
        });
        
        db.addAuditLog(createdBy, 'CREATE_USER', `Created user: ${username}`, req.ip, req.headers['user-agent']);
        res.json({ success: true, message: 'User created successfully', userId: userId });
    } catch (error) {
        console.error('Create user error:', error);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
});

app.post('/api/admin/delete-user', requireAdmin, (req, res) => {
    try {
        const { userId } = req.body;
        const deletedBy = req.session.userId;
        
        const user = db.getUserById(userId);
        if (!user) {
            return res.json({ success: false, message: 'User not found' });
        }
        
        if (userId == deletedBy) {
            return res.json({ success: false, message: 'Cannot delete yourself' });
        }
        
        const result = db.deleteUser(userId);
        if (result.changes > 0) {
            db.addAuditLog(deletedBy, 'DELETE_USER', `Deleted user: ${user.username}`, req.ip, req.headers['user-agent']);
            res.json({ success: true, message: 'User deleted successfully' });
        } else {
            res.json({ success: false, message: 'Failed to delete user' });
        }
    } catch (error) {
        console.error('Delete user error:', error);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
});

app.get('/api/maintenance/status', (req, res) => {
    try {
        const maintenance = db.getActiveMaintenance();
        res.json({ maintenance: maintenance, isMaintenance: !!maintenance });
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
                const hours = parseInt(date);
                endTime = new Date(Date.now() + hours * 60 * 60 * 1000);
            }
            
            scheduleMaintenanceEnd(endTime);
            
            const result = db.createMaintenance({
                start_time: new Date().toISOString(),
                end_time: endTime.toISOString(),
                reason: reason || 'Scheduled maintenance',
                created_by: createdBy
            });
            
            db.addAuditLog(createdBy, 'MAINTENANCE_ON', `Maintenance until ${endTime.toISOString()}`, req.ip, req.headers['user-agent']);
            
            if (telegramBot) {
                const maintenanceMessage = 
                    `🔧 *Maintenance Started*\n\n` +
                    `*Ends:* ${endTime.toISOString()}\n` +
                    `*Reason:* ${reason || 'Scheduled maintenance'}`;
                
                sendMessageToAdmin(maintenanceMessage);
            }
            
            res.json({ success: true, message: 'Maintenance mode activated', endTime: endTime.toISOString() });
        } else if (action === 'off') {
            const activeMaintenance = db.getActiveMaintenance();
            if (activeMaintenance) {
                db.endMaintenance(activeMaintenance.id);
                db.addAuditLog(createdBy, 'MAINTENANCE_OFF', 'Maintenance ended', req.ip, req.headers['user-agent']);
                
                if (telegramBot) {
                    sendMessageToAdmin('✅ *Maintenance Ended*');
                }
                
                res.json({ success: true, message: 'Maintenance mode deactivated' });
            } else {
                res.json({ success: false, message: 'No active maintenance found' });
            }
        } else {
            res.json({ success: false, message: 'Invalid action' });
        }
    } catch (error) {
        console.error('Maintenance error:', error);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
});

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

app.get('/api/dashboard-data', requireAuth, (req, res) => {
    try {
        const userId = req.session.userId;
        const user = db.getUserById(userId);
        const stats = db.getUserStatistics(userId);
        const bots = db.getUserBots(userId);
        const subscription = db.getUserSubscription(userId);
        const maintenance = db.getActiveMaintenance();
        
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

app.post('/api/bot/connect', requireAuth, (req, res) => {
    try {
        const userId = req.session.userId;
        const { phoneNumber } = req.body;
        
        const maintenance = db.getActiveMaintenance();
        if (maintenance) {
            const user = db.getUserById(userId);
            if (user.status !== 'admin') {
                return res.json({ success: false, message: 'Cannot connect bot during maintenance' });
            }
        }
        
        const result = db.createBot(userId, phoneNumber);
        const pairingCode = `QR-${phoneNumber}-${Date.now().toString(36).toUpperCase()}`;
        
        db.addAuditLog(userId, 'BOT_CONNECT', `Connected bot: ${phoneNumber}`, req.ip, req.headers['user-agent']);
        
        if (telegramBot) {
            const user = db.getUserById(userId);
            const botMessage = 
                `🤖 *Bot Connected*\n\n` +
                `*User:* ${user.username}\n` +
                `*Phone:* ${phoneNumber}\n` +
                `*Code:* ${pairingCode}`;
            
            sendMessageToAdmin(botMessage);
        }
        
        res.json({ success: true, botId: result.lastInsertRowid, pairingCode: pairingCode });
    } catch (error) {
        console.error('Bot connect error:', error);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
});

app.get('*.html', (req, res) => {
    const filePath = path.join(__dirname, req.path);
    fs.access(filePath, fs.constants.F_OK, (err) => {
        if (err) {
            res.redirect('/index.html');
        } else {
            res.sendFile(filePath);
        }
    });
});

// =============== WEBSOCKET ===============
io.on('connection', (socket) => {
    console.log('New client connected');
    
    const clientsCount = io.engine.clientsCount;
    io.emit('connection-count', { count: clientsCount });
    
    const maintenance = db.getActiveMaintenance();
    socket.emit('maintenance-status', {
        maintenance: !!maintenance,
        endTime: maintenance?.end_time
    });
    
    socket.on('disconnect', () => {
        console.log('Client disconnected');
        const clientsCount = io.engine.clientsCount;
        io.emit('connection-count', { count: clientsCount });
    });
});

// =============== ERROR HANDLERS ===============
app.use((req, res) => {
    res.status(404).send(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>404 - Page Not Found</title>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    text-align: center;
                    padding: 50px;
                    background: linear-gradient(45deg, #0a0a0a, #1a1a2e);
                    color: white;
                    min-height: 100vh;
                    display: flex;
                    flex-direction: column;
                    justify-content: center;
                    align-items: center;
                }
                h1 { color: #ff6b6b; font-size: 48px; margin-bottom: 20px; }
                p { color: #aaa; font-size: 18px; margin-bottom: 30px; }
                a {
                    color: #00b4db;
                    text-decoration: none;
                    font-size: 16px;
                    padding: 10px 20px;
                    border: 1px solid #00b4db;
                    border-radius: 5px;
                    transition: all 0.3s;
                }
                a:hover { background: #00b4db; color: white; }
            </style>
        </head>
        <body>
            <h1>404 - Page Not Found</h1>
            <p>The page you are looking for does not exist.</p>
            <a href="/">Go to Homepage</a>
        </body>
        </html>
    `);
});

app.use((err, req, res, next) => {
    console.error('Server Error:', err.stack);
    res.status(500).send(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>500 - Server Error</title>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    text-align: center;
                    padding: 50px;
                    background: linear-gradient(45deg, #0a0a0a, #1a1a2e);
                    color: white;
                    min-height: 100vh;
                    display: flex;
                    flex-direction: column;
                    justify-content: center;
                    align-items: center;
                }
                h1 { color: #ff6b6b; font-size: 48px; margin-bottom: 20px; }
                p { color: #aaa; font-size: 18px; margin-bottom: 30px; }
                a {
                    color: #00b4db;
                    text-decoration: none;
                    font-size: 16px;
                    padding: 10px 20px;
                    border: 1px solid #00b4db;
                    border-radius: 5px;
                    transition: all 0.3s;
                }
                a:hover { background: #00b4db; color: white; }
            </style>
        </head>
        <body>
            <h1>500 - Internal Server Error</h1>
            <p>Something went wrong. Please try again later.</p>
            <a href="/">Go to Homepage</a>
        </body>
        </html>
    `);
});

// =============== MAINTENANCE SCHEDULER ===============
function scheduleMaintenanceEnd(endTime) {
    const job = schedule.scheduleJob(endTime, function() {
        console.log('Maintenance auto-ended at', new Date());
        
        if (telegramBot) {
            const message = `✅ *Maintenance Auto-Completed*\n\n*Time:* ${new Date().toISOString()}`;
            sendMessageToAdmin(message);
        }
    });
    console.log('Maintenance auto-end scheduled for', endTime);
}

// =============== START SERVER ===============
server.listen(PORT, '0.0.0.0', () => {
    console.log(`
========================================
🚀 WhatsApp Bot Dashboard Started!
========================================
✅ Port: ${PORT}
✅ Environment: ${NODE_ENV}
✅ Healthcheck: http://0.0.0.0:${PORT}/health
✅ Admin ID: ${ADMIN_ID}
✅ Telegram Bot: ${telegramBot ? 'Active' : 'Disabled'}
✅ Database Type: ${dbType}
✅ Railway Hosting: Active
========================================
    `);
    
    if (telegramBot) {
        setTimeout(async () => {
            const stats = getServerStats();
            const startMessage = 
                `🚀 *Bot Started on Railway!*\n\n` +
                `🤖 WhatsApp Bot Dashboard\n` +
                `🚂 Platform: Railway\n` +
                `🌐 Environment: ${NODE_ENV}\n` +
                `📊 Memory: ${stats.memory.usage}\n` +
                `⚙️ CPU: ${stats.cpu.usage}\n` +
                `✅ Status: Online`;
            
            sendMessageToAdmin(startMessage);
        }, 3000);
    }
});
