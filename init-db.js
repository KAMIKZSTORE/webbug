const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

// Initialize database
const db = new Database('database.db');

// Create tables
db.exec(`
    -- Users table
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        email TEXT,
        full_name TEXT,
        phone TEXT,
        status TEXT DEFAULT 'user',
        plan TEXT DEFAULT 'Basic',
        api_key TEXT UNIQUE,
        subscription_expiry DATETIME,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        last_login DATETIME,
        is_active BOOLEAN DEFAULT 1,
        created_by INTEGER,
        FOREIGN KEY (created_by) REFERENCES users (id)
    );

    -- Bots table
    CREATE TABLE IF NOT EXISTS bots (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        phone_number TEXT NOT NULL,
        status TEXT DEFAULT 'inactive',
        connection_data TEXT,
        last_active DATETIME,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    );

    -- Statistics table
    CREATE TABLE IF NOT EXISTS statistics (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        date DATE DEFAULT CURRENT_DATE,
        messages_sent INTEGER DEFAULT 0,
        bots_active INTEGER DEFAULT 0,
        FOREIGN KEY (user_id) REFERENCES users (id),
        UNIQUE(user_id, date)
    );

    -- User settings table
    CREATE TABLE IF NOT EXISTS user_settings (
        user_id INTEGER PRIMARY KEY,
        theme TEXT DEFAULT 'dark',
        notifications BOOLEAN DEFAULT 1,
        two_factor BOOLEAN DEFAULT 0,
        FOREIGN KEY (user_id) REFERENCES users (id)
    );

    -- Subscriptions table
    CREATE TABLE IF NOT EXISTS subscriptions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        plan_name TEXT NOT NULL,
        price REAL NOT NULL,
        start_date DATETIME NOT NULL,
        end_date DATETIME NOT NULL,
        auto_renew BOOLEAN DEFAULT 1,
        status TEXT DEFAULT 'active',
        FOREIGN KEY (user_id) REFERENCES users (id)
    );

    -- Plans table
    CREATE TABLE IF NOT EXISTS plans (
        name TEXT PRIMARY KEY,
        price REAL DEFAULT 0,
        max_bots INTEGER DEFAULT 1,
        max_messages_per_day INTEGER DEFAULT 100,
        features TEXT,
        is_active BOOLEAN DEFAULT 1,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    -- Statuses table
    CREATE TABLE IF NOT EXISTS statuses (
        name TEXT PRIMARY KEY,
        level INTEGER DEFAULT 0,
        permissions TEXT,
        is_active BOOLEAN DEFAULT 1,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    -- Maintenance table
    CREATE TABLE IF NOT EXISTS maintenance (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        start_time DATETIME NOT NULL,
        end_time DATETIME NOT NULL,
        reason TEXT,
        is_active BOOLEAN DEFAULT 1,
        created_by INTEGER,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (created_by) REFERENCES users (id)
    );

    -- Audit log table
    CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        action TEXT NOT NULL,
        details TEXT,
        ip_address TEXT,
        user_agent TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    );
`);

// Insert default plans
const plans = [
    { name: 'Basic', price: 0, max_bots: 1, max_messages_per_day: 100, features: 'Basic features, 1 bot' },
    { name: 'Premium', price: 9.99, max_bots: 3, max_messages_per_day: 1000, features: 'Premium features, 3 bots' },
    { name: 'Vip', price: 19.99, max_bots: 5, max_messages_per_day: 5000, features: 'VIP features, 5 bots' },
    { name: 'Verified', price: 29.99, max_bots: 10, max_messages_per_day: 10000, features: 'Verified features, 10 bots' },
    { name: 'Admin', price: 49.99, max_bots: 20, max_messages_per_day: 50000, features: 'Admin features, 20 bots' },
    { name: 'Developer', price: 99.99, max_bots: 50, max_messages_per_day: 100000, features: 'Developer features, 50 bots' },
    { name: 'Hacker', price: 199.99, max_bots: 100, max_messages_per_day: 1000000, features: 'Hacker features, 100 bots' },
    { name: 'Reseller', price: 149.99, max_bots: 200, max_messages_per_day: 5000000, features: 'Reseller features, 200 bots' }
];

const insertPlan = db.prepare(`
    INSERT OR IGNORE INTO plans (name, price, max_bots, max_messages_per_day, features)
    VALUES (?, ?, ?, ?, ?)
`);

plans.forEach(plan => {
    insertPlan.run(plan.name, plan.price, plan.max_bots, plan.max_messages_per_day, plan.features);
});

// Insert default statuses
const statuses = [
    { name: 'user', level: 1, permissions: 'basic_access' },
    { name: 'dev', level: 2, permissions: 'developer_access' },
    { name: 'admin', level: 3, permissions: 'full_access' }
];

const insertStatus = db.prepare(`
    INSERT OR IGNORE INTO statuses (name, level, permissions)
    VALUES (?, ?, ?)
`);

statuses.forEach(status => {
    insertStatus.run(status.name, status.level, status.permissions);
});

// Insert default admin user if not exists
const checkAdmin = db.prepare('SELECT COUNT(*) as count FROM users WHERE username = ?').get('admin');
if (checkAdmin.count === 0) {
    const hashedPassword = bcrypt.hashSync('admin123', 10);
    const apiKey = 'sk_live_' + crypto.randomBytes(16).toString('hex');
    
    const insertUser = db.prepare(`
        INSERT INTO users (username, password, email, full_name, status, plan, api_key, subscription_expiry)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);
    
    insertUser.run(
        'admin',
        hashedPassword,
        'admin@whatsappbot.com',
        'Administrator',
        'admin',
        'Admin',
        apiKey,
        new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString()
    );
    
    const userId = db.prepare('SELECT last_insert_rowid() as id').get().id;
    
    // Insert subscription
    const insertSub = db.prepare(`
        INSERT INTO subscriptions (user_id, plan_name, price, start_date, end_date)
        VALUES (?, ?, ?, ?, ?)
    `);
    
    insertSub.run(
        userId,
        'Admin',
        49.99,
        new Date().toISOString(),
        new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString()
    );
    
    // Insert settings
    const insertSettings = db.prepare(`
        INSERT INTO user_settings (user_id) VALUES (?)
    `);
    
    insertSettings.run(userId);
    
    // Insert initial statistics
    const insertStats = db.prepare(`
        INSERT INTO statistics (user_id, messages_sent, bots_active)
        VALUES (?, ?, ?)
    `);
    
    insertStats.run(userId, 45678, 3);
    
    console.log('╔══════════════════════════════════════════════════╗');
    console.log('║           WhatsApp Bot Database Created          ║');
    console.log('╠══════════════════════════════════════════════════╣');
    console.log('║ Default Admin User Created:                      ║');
    console.log('║                                                  ║');
    console.log('║ Username: admin                                  ║');
    console.log('║ Password: admin123                               ║');
    console.log('║ Status: admin                                    ║');
    console.log('║ Plan: Admin                                      ║');
    console.log('║ API Key: ' + apiKey + ' ║');
    console.log('║                                                  ║');
    console.log('║ Telegram Commands:                               ║');
    console.log('║ /create <username> <password> <expired> <plan> <status>║');
    console.log('║ /delete <username>                               ║');
    console.log('║ /maintenance <time> <on/off> <reason>            ║');
    console.log('║ /listusers /listplans /liststatus                ║');
    console.log('╚══════════════════════════════════════════════════╝');
}

console.log('\n✅ Database initialized successfully!');
db.close();
