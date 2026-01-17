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

// =============== ADMIN ID ===============
const ADMIN_ID = '8443969542'; // Your admin ID
const ADMIN_USERNAME = 'admin'; // Default admin username

// =============== HEALTHCHECK WAJIB UNTUK RAILWAY ===============
const app = express();

// Route healthcheck HARUS di bagian paling atas
app.get('/health', (req, res) => {
    res.status(200).json({
        status: 'OK',
        timestamp: new Date().toISOString(),
        service: 'WhatsApp Bot Dashboard',
        uptime: process.uptime(),
        adminId: ADMIN_ID
    });
});

// =============== STATIC FILES ===============
app.use(express.static(__dirname));

// =============== MOCK DATABASE JIKA FILE TIDAK ADA ===============
let db;
let dbType = 'real';

try {
    if (fs.existsSync('./database.js')) {
        db = require('./database');
        console.log('✅ Loaded real database');
    } else {
        throw new Error('Database file not found');
    }
} catch (error) {
    console.log('⚠️ Using mock database:', error.message);
    dbType = 'mock';
    
    db = {
        getActiveMaintenance: () => null,
        getUserById: (id) => ({
            id: 1,
            username: 'admin',
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
            if (username === 'admin') {
                return {
                    id: 1,
                    username: 'admin',
                    password: bcrypt.hashSync('admin123', 10),
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
                    username: 'admin',
                    password: bcrypt.hashSync('admin123', 10),
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
                username: 'admin',
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

// =============== FUNGSI UNTUK STATISTIK SERVER ===============
function getServerStats() {
    try {
        const mem = process.memoryUsage();
        const cpus = os.cpus();
        const load = os.loadavg();
        const uptime = process.uptime();
        const totalMem = os.totalmem();
        const freeMem = os.freemem();
        const usedMem = totalMem - freeMem;
        
        // CPU usage calculation
        let totalIdle = 0, totalTick = 0;
        cpus.forEach((cpu) => {
            for (let type in cpu.times) {
                totalTick += cpu.times[type];
            }
            totalIdle += cpu.times.idle;
        });
        
        const cpuUsage = ((1 - totalIdle / totalTick) * 100).toFixed(2);
        
        // Format bytes to human readable
        const formatBytes = (bytes) => {
            if (bytes === 0) return '0 Bytes';
            const k = 1024;
            const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        };
        
        // Format uptime
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
                cores: cpus.length,
                model: cpus[0]?.model || 'Unknown',
                load1: load[0].toFixed(2),
                load5: load[1].toFixed(2),
                load15: load[2].toFixed(2)
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
            network: {
                interfaces: Object.keys(os.networkInterfaces()).length,
                host: os.hostname()
            },
            process: {
                uptime: formatUptime(uptime),
                memory: formatBytes(mem.rss),
                pid: process.pid,
                ppid: process.ppid,
                cwd: process.cwd()
            },
            timestamp: new Date().toISOString()
        };
    } catch (error) {
        console.error('Error getting server stats:', error);
        return { error: 'Failed to get server statistics' };
    }
}

// =============== FUNGSI UNTUK MENGIRIM PESAN KE ADMIN ===============
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

// =============== SINGLE TELEGRAM BOT ===============
let telegramBot = null;

// Inisialisasi bot Telegram
try {
    if (process.env.TELEGRAM_BOT_TOKEN) {
        const TelegramBot = require('node-telegram-bot-api');
        
        // Inisialisasi bot dengan polling
        telegramBot = new TelegramBot(process.env.TELEGRAM_BOT_TOKEN, {
            polling: {
                interval: 300,
                autoStart: true,
                params: {
                    timeout: 10
                }
            }
        });
        
        console.log('🤖 Telegram bot initialized successfully');
        console.log(`👑 Admin ID: ${ADMIN_ID}`);
        
        // Kirim notifikasi startup ke admin
        setTimeout(async () => {
            const stats = getServerStats();
            const startMessage = 
                `🚀 *Bot Started Successfully!*\n\n` +
                `🤖 *WhatsApp Bot Dashboard*\n` +
                `⏰ *Time:* ${moment().format('YYYY-MM-DD HH:mm:ss')}\n` +
                `🖥️ *Hostname:* ${stats.system.hostname}\n` +
                `📊 *Memory:* ${stats.memory.usage}\n` +
                `⚙️ *CPU:* ${stats.cpu.usage}\n` +
                `🔧 *Admin ID:* ${ADMIN_ID}\n\n` +
                `✅ Bot is ready to receive commands!`;
            
            sendMessageToAdmin(startMessage);
        }, 3000);
        
        // =============== TELEGRAM BOT COMMANDS ===============
        
        // Command /start
        telegramBot.onText(/\/start/, (msg) => {
            const chatId = msg.chat.id;
            const userId = msg.from.id;
            const username = msg.from.username || msg.from.first_name;
            
            // Check if user is admin
            const isAdmin = userId.toString() === ADMIN_ID;
            
            let welcomeMessage = `🤖 *WhatsApp Bot Control Panel*\n\n`;
            welcomeMessage += `Welcome ${username}!\n`;
            
            if (isAdmin) {
                welcomeMessage += `👑 *Status:* Administrator\n\n`;
                welcomeMessage += `*Available commands:*\n\n`;
                welcomeMessage += `📝 *User Management*\n`;
                welcomeMessage += `/createuser <username> <password> <plan> <status> <expired>\n`;
                welcomeMessage += `/deleteuser <username>\n`;
                welcomeMessage += `/listusers - Show all users\n\n`;
                welcomeMessage += `🔧 *Maintenance*\n`;
                welcomeMessage += `/maintenance <time> <on/off> <reason>\n`;
                welcomeMessage += `/maintenancestatus - Check maintenance status\n\n`;
                welcomeMessage += `📊 *Server & Info*\n`;
                welcomeMessage += `/ping - Server statistics (CPU, RAM, etc.)\n`;
                welcomeMessage += `/listplans - Show available plans\n`;
                welcomeMessage += `/liststatus - Show user statuses\n`;
                welcomeMessage += `/help - Show this message\n\n`;
                welcomeMessage += `🔔 *Notifications*\n`;
                welcomeMessage += `/broadcast <message> - Send broadcast to all users\n`;
                welcomeMessage += `/notify <message> - Send notification to admin\n\n`;
                welcomeMessage += `*Examples:*\n`;
                welcomeMessage += `✓ /createuser john123 pass123 Premium user 30d\n`;
                welcomeMessage += `✓ /maintenance 2h on "System upgrade"\n`;
                welcomeMessage += `✓ /ping - Check server health\n`;
                welcomeMessage += `✓ /broadcast "Hello everyone!"`;
            } else {
                welcomeMessage += `👤 *Status:* User\n\n`;
                welcomeMessage += `*Available commands:*\n\n`;
                welcomeMessage += `/ping - Check server status\n`;
                welcomeMessage += `/help - Show help message\n\n`;
                welcomeMessage += `*Contact admin for more features:* @${ADMIN_USERNAME}`;
            }
            
            telegramBot.sendMessage(chatId, welcomeMessage, { parse_mode: 'Markdown' });
            
            // Log access
            console.log(`User ${username} (ID: ${userId}) accessed /start command`);
        });
        
        // Command /help
        telegramBot.onText(/\/help/, (msg) => {
            const chatId = msg.chat.id;
            const userId = msg.from.id;
            const isAdmin = userId.toString() === ADMIN_ID;
            
            if (isAdmin) {
                telegramBot.sendMessage(chatId, 
                    `🆘 *Admin Help Center*\n\n` +
                    `*User Management:*\n` +
                    `• /createuser - Create new user\n` +
                    `• /deleteuser - Delete user\n` +
                    `• /listusers - List all users\n\n` +
                    `*Maintenance:*\n` +
                    `• /maintenance - Control maintenance mode\n` +
                    `• /maintenancestatus - Check status\n\n` +
                    `*Server Monitoring:*\n` +
                    `• /ping - Check server statistics\n\n` +
                    `*Notifications:*\n` +
                    `• /broadcast - Send message to all users\n` +
                    `• /notify - Send notification to admin\n\n` +
                    `*Information:*\n` +
                    `• /listplans - Show subscription plans\n` +
                    `• /liststatus - Show user statuses\n\n` +
                    `*Time Format:*\n` +
                    `• 30m = 30 minutes\n` +
                    `• 2h = 2 hours\n` +
                    `• 1d = 1 day`,
                    { parse_mode: 'Markdown' }
                );
            } else {
                telegramBot.sendMessage(chatId,
                    `🆘 *Help Center*\n\n` +
                    `*Available commands:*\n` +
                    `• /ping - Check server status\n` +
                    `• /help - Show this message\n\n` +
                    `*Need admin access?*\n` +
                    `Contact @${ADMIN_USERNAME} for assistance.`,
                    { parse_mode: 'Markdown' }
                );
            }
        });
        
        // Command /ping - SERVER STATISTICS
        telegramBot.onText(/\/ping/, async (msg) => {
            const chatId = msg.chat.id;
            const userId = msg.from.id;
            const username = msg.from.username || msg.from.first_name;
            const startTime = Date.now();
            
            try {
                // Kirim pesan "Checking..." terlebih dahulu
                const loadingMsg = await telegramBot.sendMessage(chatId, 
                    '🔄 *Checking server statistics...*',
                    { parse_mode: 'Markdown' }
                );
                
                // Dapatkan statistik server
                const stats = getServerStats();
                const pingTime = Date.now() - startTime;
                
                // Buat pesan statistik
                let message = `📊 *SERVER STATISTICS*\n\n`;
                
                // User info
                message += `👤 *User:* ${username}\n`;
                message += `🆔 *ID:* ${userId}\n`;
                message += `✅ *System Status:* ONLINE\n`;
                message += `⏱️ *Response Time:* ${pingTime}ms\n`;
                message += `📅 *Timestamp:* ${moment().format('YYYY-MM-DD HH:mm:ss')}\n\n`;
                
                // CPU Information
                message += `⚙️ *CPU INFORMATION*\n`;
                message += `   📈 Usage: ${stats.cpu.usage}\n`;
                message += `   🎯 Cores: ${stats.cpu.cores}\n`;
                message += `   📊 Load Average: ${stats.cpu.load1}, ${stats.cpu.load5}, ${stats.cpu.load15}\n\n`;
                
                // Memory Information
                message += `💾 *MEMORY USAGE*\n`;
                message += `   🗃️ Total: ${stats.memory.total}\n`;
                message += `   📦 Used: ${stats.memory.used} (${stats.memory.usage})\n`;
                message += `   📭 Free: ${stats.memory.free}\n`;
                message += `   🧠 Heap: ${stats.memory.heapUsed} / ${stats.memory.heapTotal}\n`;
                message += `   📄 RSS: ${stats.memory.rss}\n\n`;
                
                // System Information
                message += `🖥️ *SYSTEM INFORMATION*\n`;
                message += `   🏷️ Platform: ${stats.system.platform}\n`;
                message += `   🏗️ Architecture: ${stats.system.arch}\n`;
                message += `   🖥️ Hostname: ${stats.system.hostname}\n`;
                message += `   📦 Node.js: ${stats.system.nodeVersion}\n\n`;
                
                // Uptime Information
                message += `⏰ *UPTIME*\n`;
                message += `   🔄 Process: ${stats.system.uptime}\n`;
                message += `   🖥️ System: ${stats.system.osUptime}\n\n`;
                
                // Tampilkan health status berdasarkan penggunaan
                const cpuUsage = parseFloat(stats.cpu.usage);
                const memUsage = parseFloat(stats.memory.usage);
                
                let healthStatus = '🟢 EXCELLENT';
                let healthMessage = 'Server is running optimally';
                
                if (cpuUsage > 80 || memUsage > 85) {
                    healthStatus = '🔴 CRITICAL';
                    healthMessage = 'Server under heavy load';
                } else if (cpuUsage > 60 || memUsage > 70) {
                    healthStatus = '🟠 WARNING';
                    healthMessage = 'Server load is high';
                } else if (cpuUsage > 40 || memUsage > 50) {
                    healthStatus = '🟡 MODERATE';
                    healthMessage = 'Server load is moderate';
                }
                
                message += `📈 *HEALTH STATUS: ${healthStatus}*\n`;
                message += `💬 ${healthMessage}\n\n`;
                
                // Database Status
                message += `🗄️ *DATABASE STATUS*\n`;
                message += `   📊 Type: ${dbType === 'real' ? '✅ Real Database' : '⚠️ Mock Database'}\n`;
                
                // Bot Status
                message += `\n🤖 *BOT STATUS*\n`;
                message += `   Telegram: ✅ Active\n`;
                message += `   Total Users: ${db.getAllUsers().length}\n`;
                
                // Admin status
                if (userId.toString() === ADMIN_ID) {
                    message += `   👑 Admin: ✅ You are administrator\n`;
                }
                
                // Maintenance Status
                const maintenance = db.getActiveMaintenance();
                if (maintenance) {
                    const endTime = moment(maintenance.end_time).format('MMM DD, HH:mm');
                    message += `\n⚠️ *MAINTENANCE ACTIVE*\n`;
                    message += `   Ends: ${endTime}\n`;
                    message += `   Reason: ${maintenance.reason || 'Not specified'}`;
                }
                
                // Edit pesan loading dengan hasil
                await telegramBot.editMessageText(message, {
                    chat_id: chatId,
                    message_id: loadingMsg.message_id,
                    parse_mode: 'Markdown'
                });
                
                // Log ping request
                console.log(`User ${username} (ID: ${userId}) requested server stats`);
                
            } catch (error) {
                console.error('Telegram ping error:', error);
                telegramBot.sendMessage(chatId,
                    '❌ *Error getting server statistics*\n\n' +
                    'Please try again later.',
                    { parse_mode: 'Markdown' }
                );
            }
        });
        
        // Command /broadcast (Admin only)
        telegramBot.onText(/\/broadcast (.+)/, async (msg, match) => {
            const chatId = msg.chat.id;
            const userId = msg.from.id;
            
            // Verifikasi admin
            if (userId.toString() !== ADMIN_ID) {
                return telegramBot.sendMessage(chatId, 
                    '❌ *Access Denied*\n\nOnly administrators can send broadcast messages.',
                    { parse_mode: 'Markdown' }
                );
            }
            
            const message = match[1].trim();
            if (!message) {
                return telegramBot.sendMessage(chatId,
                    '❌ *Usage:*\n' +
                    '`/broadcast <message>`\n\n' +
                    '*Example:*\n' +
                    '`/broadcast Server maintenance in 10 minutes`',
                    { parse_mode: 'Markdown' }
                );
            }
            
            try {
                // Kirim broadcast ke semua user yang diketahui
                const users = db.getAllUsers();
                let successCount = 0;
                let failCount = 0;
                
                const broadcastMessage = 
                    `📢 *BROADCAST MESSAGE*\n\n` +
                    `${message}\n\n` +
                    `*From:* Administrator\n` +
                    `*Time:* ${moment().format('YYYY-MM-DD HH:mm:ss')}`;
                
                // Kirim ke admin dulu sebagai preview
                await telegramBot.sendMessage(chatId,
                    `📤 *Sending broadcast...*\n\n` +
                    `Message: ${message}\n` +
                    `Total recipients: ${users.length}`,
                    { parse_mode: 'Markdown' }
                );
                
                // Kirim ke semua user
                for (const user of users) {
                    if (user.telegram_id && user.telegram_id !== ADMIN_ID) {
                        try {
                            await telegramBot.sendMessage(user.telegram_id, broadcastMessage, { parse_mode: 'Markdown' });
                            successCount++;
                        } catch (error) {
                            failCount++;
                            console.error(`Failed to send to user ${user.username}:`, error.message);
                        }
                    }
                }
                
                // Report hasil
                await telegramBot.sendMessage(chatId,
                    `✅ *Broadcast Complete!*\n\n` +
                    `📤 Sent to: ${successCount} users\n` +
                    `❌ Failed: ${failCount} users\n` +
                    `📊 Success rate: ${((successCount / users.length) * 100).toFixed(1)}%`,
                    { parse_mode: 'Markdown' }
                );
                
                // Log broadcast
                console.log(`Admin broadcasted message to ${successCount} users`);
                
            } catch (error) {
                console.error('Telegram broadcast error:', error);
                telegramBot.sendMessage(chatId,
                    '❌ *Error sending broadcast*',
                    { parse_mode: 'Markdown' }
                );
            }
        });
        
        // Command /notify (Send notification to admin)
        telegramBot.onText(/\/notify (.+)/, async (msg, match) => {
            const chatId = msg.chat.id;
            const userId = msg.from.id;
            const username = msg.from.username || msg.from.first_name;
            const message = match[1].trim();
            
            if (!message) {
                return telegramBot.sendMessage(chatId,
                    '❌ *Usage:*\n' +
                    '`/notify <message>`\n\n' +
                    '*Example:*\n' +
                    '`/notify Need help with bot configuration`',
                    { parse_mode: 'Markdown' }
                );
            }
            
            try {
                // Kirim notifikasi ke admin
                const notificationMessage = 
                    `📩 *NEW NOTIFICATION*\n\n` +
                    `*From:* ${username}\n` +
                    `*User ID:* ${userId}\n` +
                    `*Time:* ${moment().format('YYYY-MM-DD HH:mm:ss')}\n\n` +
                    `*Message:*\n${message}`;
                
                const sent = await sendMessageToAdmin(notificationMessage);
                
                if (sent) {
                    telegramBot.sendMessage(chatId,
                        `✅ *Notification sent to admin!*\n\n` +
                        `Your message has been delivered to the administrator.`,
                        { parse_mode: 'Markdown' }
                    );
                } else {
                    telegramBot.sendMessage(chatId,
                        '❌ *Failed to send notification*\n\n' +
                        'Please try again later or contact admin directly.',
                        { parse_mode: 'Markdown' }
                    );
                }
                
            } catch (error) {
                console.error('Telegram notify error:', error);
                telegramBot.sendMessage(chatId,
                    '❌ *Error sending notification*',
                    { parse_mode: 'Markdown' }
                );
            }
        });
        
        // Command /createuser (Admin only)
        telegramBot.onText(/\/createuser (.+)/, async (msg, match) => {
            const chatId = msg.chat.id;
            const userId = msg.from.id;
            
            // Verifikasi admin
            if (userId.toString() !== ADMIN_ID) {
                return telegramBot.sendMessage(chatId, 
                    '❌ *Access Denied*\n\nOnly administrators can create users.',
                    { parse_mode: 'Markdown' }
                );
            }
            
            const args = match[1].split(' ');
            if (args.length < 5) {
                return telegramBot.sendMessage(chatId,
                    '❌ *Usage:*\n' +
                    '`/createuser <username> <password> <plan> <status> <expired>`\n\n' +
                    '*Example:*\n' +
                    '`/createuser john123 pass123 Premium user 30d`\n\n' +
                    '*Plans:* Free, Premium, VIP\n' +
                    '*Status:* user, admin',
                    { parse_mode: 'Markdown' }
                );
            }
            
            const [username, password, plan, status, expired] = args;
            
            try {
                // Validasi plan
                const validPlans = db.getAllPlans().map(p => p.name);
                if (!validPlans.includes(plan)) {
                    return telegramBot.sendMessage(chatId,
                        `❌ *Invalid Plan*\n\nAvailable plans: ${validPlans.join(', ')}`,
                        { parse_mode: 'Markdown' }
                    );
                }
                
                // Validasi status
                const validStatuses = db.getAllStatuses().map(s => s.name);
                if (!validStatuses.includes(status)) {
                    return telegramBot.sendMessage(chatId,
                        `❌ *Invalid Status*\n\nAvailable statuses: ${validStatuses.join(', ')}`,
                        { parse_mode: 'Markdown' }
                    );
                }
                
                // Cek user sudah ada
                const existingUser = db.getUserByUsername(username);
                if (existingUser) {
                    return telegramBot.sendMessage(chatId,
                        '❌ *Username already exists*',
                        { parse_mode: 'Markdown' }
                    );
                }
                
                // Buat user
                const userIdResult = db.createUser({
                    username,
                    password: bcrypt.hashSync(password, 10),
                    plan,
                    status,
                    expired,
                    created_by: 1, // Admin ID
                    email: `${username}@whatsappbot.com`,
                    full_name: username
                });
                
                // Log audit
                db.addAuditLog(1, 'TG_CREATE_USER', 
                    `Created user via Telegram: ${username}`, 
                    'telegram', 'telegram-bot'
                );
                
                const resultMessage = 
                    `✅ *User Created Successfully!*\n\n` +
                    `👤 *Username:* ${username}\n` +
                    `🔑 *Password:* ${password}\n` +
                    `📅 *Plan:* ${plan}\n` +
                    `👑 *Status:* ${status}\n` +
                    `⏰ *Expires:* ${expired}\n` +
                    `🆔 *User ID:* ${userIdResult.lastInsertRowid}\n\n` +
                    `*Created by:* Administrator\n` +
                    `*Time:* ${moment().format('YYYY-MM-DD HH:mm:ss')}`;
                
                telegramBot.sendMessage(chatId, resultMessage, { parse_mode: 'Markdown' });
                
                // Kirim notifikasi ke user jika memiliki telegram_id
                // (Dalam implementasi nyata, Anda perlu mendapatkan telegram_id user)
                
            } catch (error) {
                console.error('Telegram create user error:', error);
                telegramBot.sendMessage(chatId,
                    '❌ *Error creating user*\n\nPlease try again later.',
                    { parse_mode: 'Markdown' }
                );
            }
        });
        
        // Command /deleteuser (Admin only)
        telegramBot.onText(/\/deleteuser (.+)/, async (msg, match) => {
            const chatId = msg.chat.id;
            const userId = msg.from.id;
            
            // Verifikasi admin
            if (userId.toString() !== ADMIN_ID) {
                return telegramBot.sendMessage(chatId,
                    '❌ *Access Denied*\n\nOnly administrators can delete users.',
                    { parse_mode: 'Markdown' }
                );
            }
            
            const username = match[1].trim();
            
            try {
                // Cari user
                const user = db.getUserByUsername(username);
                if (!user) {
                    return telegramBot.sendMessage(chatId,
                        '❌ *User not found*',
                        { parse_mode: 'Markdown' }
                    );
                }
                
                // Tidak boleh menghapus diri sendiri
                if (user.username === ADMIN_USERNAME) {
                    return telegramBot.sendMessage(chatId,
                        '❌ *Cannot delete administrator account*',
                        { parse_mode: 'Markdown' }
                    );
                }
                
                // Hapus user
                db.deleteUser(user.id);
                
                // Log audit
                db.addAuditLog(1, 'TG_DELETE_USER',
                    `Deleted user via Telegram: ${username}`,
                    'telegram', 'telegram-bot'
                );
                
                telegramBot.sendMessage(chatId,
                    `✅ *User Deleted Successfully!*\n\n` +
                    `👤 *Username:* ${username}\n` +
                    `🗑️ *Status:* Removed from system\n` +
                    `*Deleted by:* Administrator\n` +
                    `*Time:* ${moment().format('YYYY-MM-DD HH:mm:ss')}`,
                    { parse_mode: 'Markdown' }
                );
                
            } catch (error) {
                console.error('Telegram delete user error:', error);
                telegramBot.sendMessage(chatId,
                    '❌ *Error deleting user*',
                    { parse_mode: 'Markdown' }
                );
            }
        });
        
        // Command /listusers (Admin only)
        telegramBot.onText(/\/listusers/, async (msg) => {
            const chatId = msg.chat.id;
            const userId = msg.from.id;
            
            // Verifikasi admin
            if (userId.toString() !== ADMIN_ID) {
                return telegramBot.sendMessage(chatId,
                    '❌ *Access Denied*\n\nOnly administrators can list users.',
                    { parse_mode: 'Markdown' }
                );
            }
            
            try {
                const users = db.getAllUsers();
                if (!users || users.length === 0) {
                    return telegramBot.sendMessage(chatId,
                        '📭 *No users found*',
                        { parse_mode: 'Markdown' }
                    );
                }
                
                let message = `📋 *User List (${users.length} users):*\n\n`;
                
                users.forEach((user, index) => {
                    const expiry = user.subscription_expiry 
                        ? moment(user.subscription_expiry).format('MMM DD, YYYY')
                        : 'N/A';
                    
                    const telegramInfo = user.telegram_id ? `TG: ${user.telegram_id}` : 'No Telegram';
                    
                    message += `*${index + 1}. ${user.username}*\n`;
                    message += `   👑 Status: ${user.status}\n`;
                    message += `   📅 Plan: ${user.plan}\n`;
                    message += `   ⏰ Expires: ${expiry}\n`;
                    message += `   📱 ${telegramInfo}\n`;
                    message += `   📧 Email: ${user.email || 'N/A'}\n`;
                    message += `   ---\n`;
                });
                
                // Split message jika terlalu panjang
                if (message.length > 4000) {
                    const chunks = message.match(/[\s\S]{1,4000}/g);
                    for (const chunk of chunks) {
                        await telegramBot.sendMessage(chatId, chunk, { parse_mode: 'Markdown' });
                    }
                } else {
                    await telegramBot.sendMessage(chatId, message, { parse_mode: 'Markdown' });
                }
                
            } catch (error) {
                console.error('Telegram list users error:', error);
                telegramBot.sendMessage(chatId,
                    '❌ *Error listing users*',
                    { parse_mode: 'Markdown' }
                );
            }
        });
        
        // Command /maintenance (Admin only)
        telegramBot.onText(/\/maintenance (.+)/, async (msg, match) => {
            const chatId = msg.chat.id;
            const userId = msg.from.id;
            
            // Verifikasi admin
            if (userId.toString() !== ADMIN_ID) {
                return telegramBot.sendMessage(chatId,
                    '❌ *Access Denied*\n\nOnly administrators can manage maintenance.',
                    { parse_mode: 'Markdown' }
                );
            }
            
            const args = match[1].split(' ');
            if (args.length < 2) {
                return telegramBot.sendMessage(chatId,
                    '❌ *Usage:*\n' +
                    '`/maintenance <time> <on/off> <reason>`\n\n' +
                    '*Examples:*\n' +
                    '✓ `/maintenance 2h on "System upgrade"`\n' +
                    '✓ `/maintenance 30m on "Emergency fix"`\n' +
                    '✓ `/maintenance 0 off`\n\n' +
                    '*Time format:* 30m, 2h, 1d',
                    { parse_mode: 'Markdown' }
                );
            }
            
            const [time, action] = args;
            const reason = args.slice(2).join(' ') || 'Scheduled maintenance';
            
            if (!['on', 'off'].includes(action.toLowerCase())) {
                return telegramBot.sendMessage(chatId,
                    '❌ *Invalid Action*\n\nUse "on" to enable or "off" to disable.',
                    { parse_mode: 'Markdown' }
                );
            }
            
            try {
                if (action === 'on') {
                    // Parse waktu
                    let endTime;
                    if (time.includes('h')) {
                        const hours = parseInt(time);
                        endTime = new Date(Date.now() + hours * 60 * 60 * 1000);
                    } else if (time.includes('d')) {
                        const days = parseInt(time);
                        endTime = new Date(Date.now() + days * 24 * 60 * 60 * 1000);
                    } else if (time.includes('m')) {
                        const minutes = parseInt(time);
                        endTime = new Date(Date.now() + minutes * 60 * 1000);
                    } else {
                        return telegramBot.sendMessage(chatId,
                            '❌ *Invalid Time Format*\n\nUse: 30m (minutes), 2h (hours), 1d (days)',
                            { parse_mode: 'Markdown' }
                        );
                    }
                    
                    // Schedule auto-end
                    scheduleMaintenanceEnd(endTime);
                    
                    // Buat maintenance record
                    db.createMaintenance({
                        start_time: new Date().toISOString(),
                        end_time: endTime.toISOString(),
                        reason: reason,
                        created_by: 1 // Admin ID
                    });
                    
                    // Log audit
                    db.addAuditLog(1, 'TG_MAINTENANCE_ON',
                        `Maintenance via Telegram until ${endTime.toISOString()}`,
                        'telegram', 'telegram-bot'
                    );
                    
                    const endTimeStr = moment(endTime).format('YYYY-MM-DD HH:mm:ss');
                    
                    telegramBot.sendMessage(chatId,
                        `⚠️ *Maintenance Mode Activated!*\n\n` +
                        `🕒 *Ends at:* ${endTimeStr}\n` +
                        `📝 *Reason:* ${reason}\n` +
                        `🔒 *Note:* Only admins can access during maintenance.\n\n` +
                        `*Activated by:* Administrator`,
                        { parse_mode: 'Markdown' }
                    );
                    
                    // Kirim broadcast tentang maintenance
                    const broadcastMessage = 
                        `⚠️ *MAINTENANCE NOTICE*\n\n` +
                        `The system will undergo maintenance.\n` +
                        `*Start:* Now\n` +
                        `*End:* ${endTimeStr}\n` +
                        `*Reason:* ${reason}\n\n` +
                        `Please save your work.`;
                    
                    // Kirim ke semua user
                    const users = db.getAllUsers();
                    for (const user of users) {
                        if (user.telegram_id && user.telegram_id !== ADMIN_ID) {
                            try {
                                await telegramBot.sendMessage(user.telegram_id, broadcastMessage, { parse_mode: 'Markdown' });
                            } catch (error) {
                                console.error(`Failed to send maintenance notice to user ${user.username}`);
                            }
                        }
                    }
                    
                } else if (action === 'off') {
                    // Matikan maintenance
                    const activeMaintenance = db.getActiveMaintenance();
                    if (activeMaintenance) {
                        db.endMaintenance(activeMaintenance.id);
                        
                        // Log audit
                        db.addAuditLog(1, 'TG_MAINTENANCE_OFF',
                            'Maintenance ended via Telegram',
                            'telegram', 'telegram-bot'
                        );
                        
                        telegramBot.sendMessage(chatId,
                            '✅ *Maintenance Mode Deactivated!*\n\n' +
                            '🌐 Website is now accessible to all users.\n\n' +
                            '*Deactivated by:* Administrator',
                            { parse_mode: 'Markdown' }
                        );
                    } else {
                        telegramBot.sendMessage(chatId,
                            'ℹ️ *No active maintenance found*',
                            { parse_mode: 'Markdown' }
                        );
                    }
                }
                
            } catch (error) {
                console.error('Telegram maintenance error:', error);
                telegramBot.sendMessage(chatId,
                    '❌ *Error managing maintenance*',
                    { parse_mode: 'Markdown' }
                );
            }
        });
        
        // Command /maintenancestatus
        telegramBot.onText(/\/maintenancestatus/, async (msg) => {
            const chatId = msg.chat.id;
            
            try {
                const maintenance = db.getActiveMaintenance();
                
                if (maintenance) {
                    const startTime = moment(maintenance.start_time).format('YYYY-MM-DD HH:mm:ss');
                    const endTime = moment(maintenance.end_time).format('YYYY-MM-DD HH:mm:ss');
                    const timeLeft = moment(maintenance.end_time).fromNow();
                    
                    telegramBot.sendMessage(chatId,
                        `🔧 *Maintenance Status: ACTIVE*\n\n` +
                        `🕐 *Started:* ${startTime}\n` +
                        `🕒 *Ends:* ${endTime}\n` +
                        `⏳ *Time left:* ${timeLeft}\n` +
                        `📝 *Reason:* ${maintenance.reason || 'Not specified'}\n\n` +
                        `⚠️ *Only administrators can access during maintenance.*`,
                        { parse_mode: 'Markdown' }
                    );
                } else {
                    telegramBot.sendMessage(chatId,
                        '✅ *Maintenance Status: INACTIVE*\n\n' +
                        '🌐 All services are running normally.',
                        { parse_mode: 'Markdown' }
                    );
                }
                
            } catch (error) {
                console.error('Telegram maintenance status error:', error);
                telegramBot.sendMessage(chatId,
                    '❌ *Error checking maintenance status*',
                    { parse_mode: 'Markdown' }
                );
            }
        });
        
        // Command /listplans
        telegramBot.onText(/\/listplans/, async (msg) => {
            const chatId = msg.chat.id;
            
            try {
                const plans = db.getAllPlans();
                
                let message = '📊 *Available Subscription Plans:*\n\n';
                
                plans.forEach((plan, index) => {
                    message += `*${index + 1}. ${plan.name} Plan*\n`;
                    message += `   💰 Price: $${plan.price}\n`;
                    message += `   🤖 Max Bots: ${plan.max_bots}\n`;
                    message += `   📨 Daily Messages: ${plan.max_messages_per_day.toLocaleString()}\n`;
                    message += `   ✨ Features: ${plan.features}\n`;
                    message += `   ---\n`;
                });
                
                telegramBot.sendMessage(chatId, message, { parse_mode: 'Markdown' });
                
            } catch (error) {
                console.error('Telegram list plans error:', error);
                telegramBot.sendMessage(chatId,
                    '❌ *Error listing plans*',
                    { parse_mode: 'Markdown' }
                );
            }
        });
        
        // Command /liststatus
        telegramBot.onText(/\/liststatus/, async (msg) => {
            const chatId = msg.chat.id;
            
            try {
                const statuses = db.getAllStatuses();
                
                let message = '👑 *Available User Statuses:*\n\n';
                
                statuses.forEach((status, index) => {
                    message += `*${index + 1}. ${status.name.toUpperCase()}*\n`;
                    message += `   📊 Level: ${status.level}\n`;
                    message += `   🔐 Permissions: ${status.permissions}\n`;
                    message += `   ---\n`;
                });
                
                telegramBot.sendMessage(chatId, message, { parse_mode: 'Markdown' });
                
            } catch (error) {
                console.error('Telegram list statuses error:', error);
                telegramBot.sendMessage(chatId,
                    '❌ *Error listing statuses*',
                    { parse_mode: 'Markdown' }
                );
            }
        });
        
        // Handler untuk semua pesan (logging)
        telegramBot.on('message', (msg) => {
            const userId = msg.from.id;
            const username = msg.from.username || msg.from.first_name;
            const chatId = msg.chat.id;
            const text = msg.text || '';
            
            // Log semua pesan dari admin
            if (userId.toString() === ADMIN_ID) {
                console.log(`👑 Admin ${username} (${userId}): ${text.substring(0, 50)}${text.length > 50 ? '...' : ''}`);
            }
        });
        
        // Handler untuk error polling
        telegramBot.on('polling_error', (error) => {
            console.error('Telegram polling error:', error);
        });
        
        // Handler untuk webhook error
        telegramBot.on('webhook_error', (error) => {
            console.error('Telegram webhook error:', error);
        });
        
        console.log('✅ All Telegram bot commands registered');
        
    } else {
        console.log('ℹ️ Telegram bot token not configured in environment variables');
    }
    
} catch (error) {
    console.error('❌ Telegram bot initialization error:', error.message);
    console.log('ℹ️ Telegram bot will be disabled');
}

const server = http.createServer(app);
const io = socketIo(server);

// =============== KODE LAYANAN UTAMA ===============

// Maintenance middleware
const checkMaintenance = async (req, res, next) => {
    try {
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
                    <title>Maintenance Mode - WhatsApp Bot</title>
                    <style>
                        * { margin: 0; padding: 0; box-sizing: border-box; }
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
                        .admin-note { color: #00ff00; font-size: 14px; margin-top: 20px; }
                        a { color: #00b4db; text-decoration: none; }
                        a:hover { text-decoration: underline; }
                    </style>
                </head>
                <body>
                    <div class="maintenance-container">
                        <div class="maintenance-icon">🛠️</div>
                        <h1>Under Maintenance</h1>
                        <p>We're currently performing scheduled maintenance to improve our service.</p>
                        <div class="countdown" id="countdown">Expected to be back ${maintenanceEnd}</div>
                        <div class="reason">
                            <strong>Reason:</strong> ${maintenance.reason || 'System upgrade and optimization'}
                        </div>
                        <p>Thank you for your patience.</p>
                        <div class="admin-note" id="adminNote"></div>
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

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Session middleware
app.use(session({
    secret: process.env.SESSION_SECRET || 'your-secret-key-change-this',
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: process.env.NODE_ENV === 'production',
        maxAge: 24 * 60 * 60 * 1000
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
            
            db.addAuditLog(user.id, 'LOGIN', 'User logged in', req.ip, req.headers['user-agent']);
            db.updateLastLogin(user.id);
            
            // Kirim notifikasi ke admin jika user login
            if (telegramBot && user.username !== ADMIN_USERNAME) {
                const loginMessage = 
                    `🔐 *User Login Alert*\n\n` +
                    `*User:* ${user.username}\n` +
                    `*Time:* ${moment().format('YYYY-MM-DD HH:mm:ss')}\n` +
                    `*IP:* ${req.ip}\n` +
                    `*Status:* ${user.status}`;
                
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

// API Routes - User Profile
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
            password,
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

// API Routes - Maintenance
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
            
            db.addAuditLog(createdBy, 'MAINTENANCE_ON', `Maintenance scheduled until ${endTime.toISOString()}`, req.ip, req.headers['user-agent']);
            
            // Kirim notifikasi ke Telegram admin
            if (telegramBot) {
                const maintenanceMessage = 
                    `🔧 *Maintenance Started*\n\n` +
                    `*Type:* Web Dashboard\n` +
                    `*Started:* ${new Date().toISOString()}\n` +
                    `*Ends:* ${endTime.toISOString()}\n` +
                    `*Reason:* ${reason || 'Scheduled maintenance'}\n` +
                    `*By:* User ID ${createdBy}`;
                
                sendMessageToAdmin(maintenanceMessage);
            }
            
            res.json({ success: true, message: 'Maintenance mode activated', endTime: endTime.toISOString() });
        } else if (action === 'off') {
            const activeMaintenance = db.getActiveMaintenance();
            if (activeMaintenance) {
                db.endMaintenance(activeMaintenance.id);
                db.addAuditLog(createdBy, 'MAINTENANCE_OFF', 'Maintenance mode ended manually', req.ip, req.headers['user-agent']);
                
                // Kirim notifikasi ke Telegram admin
                if (telegramBot) {
                    const maintenanceMessage = 
                        `✅ *Maintenance Ended*\n\n` +
                        `*Ended:* ${new Date().toISOString()}\n` +
                        `*By:* User ID ${createdBy}`;
                    
                    sendMessageToAdmin(maintenanceMessage);
                }
                
                res.json({ success: true, message: 'Maintenance mode deactivated' });
            } else {
                res.json({ success: false, message: 'No active maintenance found' });
            }
        } else {
            res.json({ success: false, message: 'Invalid action. Use "on" or "off"' });
        }
    } catch (error) {
        console.error('Maintenance error:', error);
        res.status(500).json({ success: false, message: 'Internal server error' });
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
        
        const maintenance = db.getActiveMaintenance();
        if (maintenance) {
            const user = db.getUserById(userId);
            if (user.status !== 'admin') {
                return res.json({ success: false, message: 'Cannot connect bot during maintenance' });
            }
        }
        
        const result = db.createBot(userId, phoneNumber);
        const pairingCode = `QR-${phoneNumber}-${Date.now().toString(36).toUpperCase()}`;
        
        db.addAuditLog(userId, 'BOT_CONNECT', `Initiated bot connection for ${phoneNumber}`, req.ip, req.headers['user-agent']);
        
        // Kirim notifikasi ke admin
        if (telegramBot) {
            const user = db.getUserById(userId);
            const botMessage = 
                `🤖 *New Bot Connection*\n\n` +
                `*User:* ${user.username}\n` +
                `*Phone:* ${phoneNumber}\n` +
                `*Time:* ${moment().format('YYYY-MM-DD HH:mm:ss')}\n` +
                `*Pairing Code:* ${pairingCode}`;
            
            sendMessageToAdmin(botMessage);
        }
        
        res.json({ success: true, botId: result.lastInsertRowid, pairingCode: pairingCode, message: 'Bot connection initiated' });
    } catch (error) {
        console.error('Bot connect error:', error);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
});

// Function to schedule maintenance end
function scheduleMaintenanceEnd(endTime) {
    const job = schedule.scheduleJob(endTime, function() {
        console.log('Maintenance auto-ended at', new Date());
        
        // Kirim notifikasi ke admin saat maintenance selesai
        if (telegramBot) {
            const message = 
                `✅ *Maintenance Auto-Completed*\n\n` +
                `*Ended:* ${new Date().toISOString()}\n` +
                `*Note:* Scheduled maintenance has completed automatically.`;
            
            sendMessageToAdmin(message);
        }
    });
    console.log('Maintenance auto-end scheduled for', endTime);
}

// WebSocket connection
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

// Handle semua file HTML
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

// 404 Handler
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

// Error handling middleware
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

// =============== START SERVER ===============
const PORT = process.env.PORT || 3000;
const expressServer = app.listen(PORT, '0.0.0.0', () => {
    console.log(`✅ WhatsApp Bot Dashboard running on port ${PORT}`);
    console.log(`✅ Healthcheck: http://0.0.0.0:${PORT}/health`);
    console.log(`✅ Admin ID: ${ADMIN_ID}`);
    console.log(`✅ Telegram Bot: ${telegramBot ? 'Active' : 'Disabled'}`);
    console.log(`✅ Server Stats: Available via /ping command`);
});

// Attach Socket.io ke server Express
io.attach(expressServer);
