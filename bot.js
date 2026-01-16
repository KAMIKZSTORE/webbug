const { default: makeWASocket, useMultiFileAuthState, DisconnectReason, delay } = require('@whiskeysockets/baileys');
const fs = require('fs');
const path = require('path');
const db = require('./database');

class WhatsAppBot {
    constructor() {
        this.socks = new Map(); // phoneNumber -> socket
        this.qrCodes = new Map(); // phoneNumber -> qrCode
        this.pairingCodes = new Map(); // phoneNumber -> pairingCode
    }

    async connect(phoneNumber, userId) {
        try {
            console.log(`[BOT] Connecting ${phoneNumber} for user ${userId}`);
            
            // Create auth directory
            const authDir = path.join(__dirname, 'auth', phoneNumber);
            if (!fs.existsSync(authDir)) {
                fs.mkdirSync(authDir, { recursive: true });
            }

            // Load or create auth state
            const { state, saveCreds } = await useMultiFileAuthState(authDir);

            // Create socket connection
            const sock = makeWASocket({
                auth: state,
                printQRInTerminal: true,
                browser: ['WhatsApp Bot', 'Chrome', '1.0.0']
            });

            // Store socket
            this.socks.set(phoneNumber, sock);

            // Listen for connection updates
            sock.ev.on('connection.update', (update) => {
                const { connection, lastDisconnect, qr } = update;
                
                if (qr) {
                    console.log(`[BOT] QR Code received for ${phoneNumber}`);
                    this.qrCodes.set(phoneNumber, qr);
                    
                    // Emit QR code via WebSocket if available
                    this.emitQRCode(phoneNumber, qr);
                }

                if (connection === 'close') {
                    const shouldReconnect = lastDisconnect?.error?.output?.statusCode !== 401;
                    console.log(`[BOT] Connection closed for ${phoneNumber}, reconnecting: ${shouldReconnect}`);
                    
                    // Update bot status in database
                    db.updateBotStatus(phoneNumber, 'inactive');
                    
                    if (shouldReconnect) {
                        setTimeout(() => this.connect(phoneNumber, userId), 5000);
                    }
                } else if (connection === 'open') {
                    console.log(`[BOT] Connected to WhatsApp for ${phoneNumber}`);
                    
                    // Update bot status in database
                    db.updateBotStatus(phoneNumber, 'active');
                    
                    // Emit connection status
                    this.emitConnectionStatus(phoneNumber, true);
                }
            });

            // Save credentials when updated
            sock.ev.on('creds.update', saveCreds);

            // Listen for messages
            sock.ev.on('messages.upsert', async ({ messages }) => {
                for (const msg of messages) {
                    if (msg.key.fromMe || !msg.message) continue;
                    
                    const message = msg.message.conversation || 
                                  msg.message.extendedTextMessage?.text ||
                                  msg.message.imageMessage?.caption;
                    
                    if (message) {
                        console.log(`[BOT ${phoneNumber}] Received: ${message}`);
                        
                        // Handle commands
                        if (message.startsWith('/')) {
                            await this.handleCommand(phoneNumber, userId, message, sock);
                        }
                        
                        // Increment message count for user
                        db.incrementMessagesSent(userId);
                    }
                }
            });

            return { success: true, message: 'Connection initiated' };
        } catch (error) {
            console.error(`[BOT] Connection error for ${phoneNumber}:`, error);
            return { success: false, message: error.message };
        }
    }

    async handleCommand(phoneNumber, userId, command, sock) {
        const args = command.slice(1).split(' ');
        const cmd = args[0].toLowerCase();
        
        console.log(`[BOT ${phoneNumber}] Handling command: ${cmd}`);
        
        switch (cmd) {
            case 'ping':
                await sock.sendMessage(phoneNumber, { text: '🏓 Pong!' });
                break;
                
            case 'status':
                const user = db.getUserById(userId);
                const stats = db.getUserStatistics(userId);
                await sock.sendMessage(phoneNumber, { 
                    text: `🤖 *Bot Status*\n\n` +
                         `User: ${user.username}\n` +
                         `Plan: ${user.plan}\n` +
                         `Messages: ${stats?.total_messages || 0}\n` +
                         `Bots: ${stats?.active_bots || 0}/${stats?.total_bots || 0} active`
                });
                break;
                
            case 'help':
                await sock.sendMessage(phoneNumber, { 
                    text: `📋 *Available Commands*\n\n` +
                         `/ping - Check bot response\n` +
                         `/status - Show account status\n` +
                         `/help - Show this help message\n\n` +
                         `*Admin Commands:*\n` +
                         `/create <user> <pass> <expired> <plan> <status>\n` +
                         `/delete <username>\n` +
                         `/maintenance <time> <on/off> <reason>`
                });
                break;
                
            default:
                await sock.sendMessage(phoneNumber, { 
                    text: `❓ Unknown command. Type /help for available commands.`
                });
        }
    }

    emitQRCode(phoneNumber, qrCode) {
        // This will be handled by WebSocket in index.js
        console.log(`[BOT] QR Code for ${phoneNumber}:`, qrCode);
    }

    emitConnectionStatus(phoneNumber, isConnected) {
        // This will be handled by WebSocket in index.js
        console.log(`[BOT] Connection status for ${phoneNumber}:`, isConnected ? 'Connected' : 'Disconnected');
    }

    async sendMessage(to, message) {
        const sock = this.socks.get(to);
        if (!sock) {
            throw new Error(`Bot ${to} is not connected`);
        }

        try {
            await sock.sendMessage(to, { text: message });
            return { success: true };
        } catch (error) {
            return { success: false, error: error.message };
        }
    }

    disconnect(phoneNumber) {
        const sock = this.socks.get(phoneNumber);
        if (sock) {
            sock.end();
            this.socks.delete(phoneNumber);
            this.qrCodes.delete(phoneNumber);
            this.pairingCodes.delete(phoneNumber);
        }
    }

    getQRCode(phoneNumber) {
        return this.qrCodes.get(phoneNumber);
    }

    generatePairingCode(phoneNumber) {
        const code = Math.random().toString(36).substring(2, 8).toUpperCase();
        this.pairingCodes.set(phoneNumber, code);
        return code;
    }

    getPairingCode(phoneNumber) {
        return this.pairingCodes.get(phoneNumber);
    }
}

module.exports = WhatsAppBot;
