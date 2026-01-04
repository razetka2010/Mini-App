const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const path = require('path');
const mysql = require('mysql2/promise');
const CryptoJS = require('crypto-js');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname)));

// Конфигурация базы данных (измените под свои настройки)
const dbConfig = {
    host: 'localhost',
    user: 'root',
    password: '',
    database: 'password_manager',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
};

// Создаем пул соединений
const pool = mysql.createPool(dbConfig);

// Проверка подписи Telegram (упрощенная версия)
function verifyTelegramHash(initData, botToken) {
    try {
        const params = new URLSearchParams(initData);
        const hash = params.get('hash');
        if (!hash) return false;

        // Удаляем hash из параметров
        params.delete('hash');

        // Сортируем параметры
        const sortedParams = Array.from(params.entries())
            .sort(([a], [b]) => a.localeCompare(b))
            .map(([key, value]) => `${key}=${value}`)
            .join('\n');

        // Вычисляем secret_key
        const secretKey = CryptoJS.HmacSHA256(botToken, 'WebAppData');

        // Вычисляем hash
        const calculatedHash = CryptoJS.HmacSHA256(sortedParams, secretKey).toString(CryptoJS.enc.Hex);

        return calculatedHash === hash;
    } catch (error) {
        console.error('Hash verification error:', error);
        return false;
    }
}

// API: Аутентификация
app.post('/api/auth', async (req, res) => {
    try {
        const { initData } = req.body;

        if (!initData) {
            return res.status(400).json({ success: false, message: 'No initData' });
        }

        // Парсим initData
        const params = new URLSearchParams(initData);
        const userParam = params.get('user');

        if (!userParam) {
            return res.status(400).json({ success: false, message: 'No user data' });
        }

        const user = JSON.parse(userParam);

        // Проверяем Telegram hash (для продакшена)
        // const botToken = 'ВАШ_ТОКЕН_БОТА';
        // if (!verifyTelegramHash(initData, botToken)) {
        //     return res.status(401).json({ success: false, message: 'Invalid signature' });
        // }

        // Подключаемся к базе данных
        const connection = await pool.getConnection();

        try {
            // Создаем или обновляем пользователя
            const [result] = await connection.execute(
                `INSERT INTO users (telegram_id, username, first_name, last_name)
                 VALUES (?, ?, ?, ?)
                     ON DUPLICATE KEY UPDATE
                                          username = VALUES(username),
                                          first_name = VALUES(first_name),
                                          last_name = VALUES(last_name),
                                          last_login = CURRENT_TIMESTAMP`,
                [user.id, user.username || null, user.first_name || '', user.last_name || '']
            );

            // Получаем ID пользователя
            const [rows] = await connection.execute(
                'SELECT id, telegram_id, username, first_name, last_name, created_at FROM users WHERE telegram_id = ?',
                [user.id]
            );

            // Генерируем сессионный токен
            const sessionToken = Buffer.from(JSON.stringify({
                telegram_id: user.id,
                user_id: rows[0].id,
                iat: Date.now(),
                exp: Date.now() + (7 * 24 * 60 * 60 * 1000)
            })).toString('base64');

            res.json({
                success: true,
                user: {
                    telegram: user,
                    database: rows[0]
                },
                session_token: sessionToken
            });

        } finally {
            connection.release();
        }

    } catch (error) {
        console.error('Auth error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error',
            debug: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

// API: Получить пароли
app.get('/api/passwords', async (req, res) => {
    try {
        const token = req.headers.authorization?.replace('Bearer ', '');
        if (!token) {
            return res.status(401).json({ success: false, message: 'No token' });
        }

        // Декодируем токен
        const tokenData = JSON.parse(Buffer.from(token, 'base64').toString());

        const connection = await pool.getConnection();
        try {
            const [rows] = await connection.execute(
                `SELECT id, service_name, login, encrypted_password, iv, created_at
                 FROM passwords
                 WHERE user_id = ? AND deleted_at IS NULL
                 ORDER BY created_at DESC`,
                [tokenData.user_id]
            );

            res.json({
                success: true,
                passwords: rows,
                count: rows.length
            });
        } finally {
            connection.release();
        }
    } catch (error) {
        console.error('Get passwords error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// API: Добавить пароль
app.post('/api/passwords', async (req, res) => {
    try {
        const token = req.headers.authorization?.replace('Bearer ', '');
        if (!token) {
            return res.status(401).json({ success: false, message: 'No token' });
        }

        const tokenData = JSON.parse(Buffer.from(token, 'base64').toString());
        const { service_name, login, encrypted_password, iv } = req.body;

        if (!service_name || !login || !encrypted_password || !iv) {
            return res.status(400).json({ success: false, message: 'Missing fields' });
        }

        const connection = await pool.getConnection();
        try {
            const [result] = await connection.execute(
                `INSERT INTO passwords (user_id, service_name, login, encrypted_password, iv)
                 VALUES (?, ?, ?, ?, ?)`,
                [tokenData.user_id, service_name, login, encrypted_password, iv]
            );

            res.json({
                success: true,
                id: result.insertId,
                created_at: new Date().toISOString()
            });
        } finally {
            connection.release();
        }
    } catch (error) {
        console.error('Add password error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// API: Обновить пароль
app.put('/api/passwords/:id', async (req, res) => {
    try {
        console.log('PUT /api/passwords/:id called');
        console.log('Params:', req.params);
        console.log('Body:', req.body);

        const token = req.headers.authorization?.replace('Bearer ', '');
        if (!token) {
            console.log('No token provided');
            return res.status(401).json({ success: false, message: 'No token' });
        }

        const tokenData = JSON.parse(Buffer.from(token, 'base64').toString());
        const id = req.params.id;
        const { login, encrypted_password, iv } = req.body;

        console.log('Token data:', tokenData);
        console.log('Password ID:', id);
        console.log('Update data:', { login, encrypted_password: '...', iv: '...' });

        if (!login || !encrypted_password || !iv) {
            console.log('Missing fields');
            return res.status(400).json({
                success: false,
                message: 'Missing fields',
                received: { login: !!login, encrypted_password: !!encrypted_password, iv: !!iv }
            });
        }

        const connection = await pool.getConnection();
        try {
            console.log('Updating password in database...');

            const [result] = await connection.execute(
                `UPDATE passwords 
                 SET login = ?, encrypted_password = ?, iv = ?, updated_at = CURRENT_TIMESTAMP
                 WHERE id = ? AND user_id = ? AND deleted_at IS NULL`,
                [login, encrypted_password, iv, id, tokenData.user_id]
            );

            console.log('Update result:', result);

            if (result.affectedRows === 0) {
                console.log('No rows affected - password not found or access denied');
                return res.status(404).json({
                    success: false,
                    message: 'Password not found or access denied'
                });
            }

            res.json({
                success: true,
                updated: true,
                affectedRows: result.affectedRows,
                message: 'Password updated successfully',
                updated_at: new Date().toISOString()
            });
        } catch (dbError) {
            console.error('Database error:', dbError);
            throw dbError;
        } finally {
            connection.release();
        }
    } catch (error) {
        console.error('Update password error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error',
            error: error.message
        });
    }
});

// API: Удалить пароль
app.delete('/api/passwords/:id', async (req, res) => {
    try {
        console.log('DELETE /api/passwords/:id called');

        const token = req.headers.authorization?.replace('Bearer ', '');
        if (!token) {
            return res.status(401).json({ success: false, message: 'No token' });
        }

        const tokenData = JSON.parse(Buffer.from(token, 'base64').toString());
        const id = req.params.id;

        const connection = await pool.getConnection();
        try {
            const [result] = await connection.execute(
                `UPDATE passwords SET deleted_at = CURRENT_TIMESTAMP
                 WHERE id = ? AND user_id = ?`,
                [id, tokenData.user_id]
            );

            res.json({
                success: result.affectedRows > 0,
                deleted: result.affectedRows > 0,
                affectedRows: result.affectedRows
            });
        } finally {
            connection.release();
        }
    } catch (error) {
        console.error('Delete password error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// SQL для создания таблиц
app.get('/api/init-db', async (req, res) => {
    try {
        const connection = await pool.getConnection();
        try {
            // Создаем таблицу users
            await connection.execute(`
                CREATE TABLE IF NOT EXISTS users (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    telegram_id BIGINT UNIQUE NOT NULL,
                    username VARCHAR(255),
                    first_name VARCHAR(255),
                    last_name VARCHAR(255),
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP NULL
                )
            `);

            // Создаем таблицу passwords
            await connection.execute(`
                CREATE TABLE IF NOT EXISTS passwords (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    user_id INT NOT NULL,
                    service_name VARCHAR(255) NOT NULL,
                    login VARCHAR(255) NOT NULL,
                    encrypted_password TEXT NOT NULL,
                    iv VARCHAR(32) NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP NULL,
                    deleted_at TIMESTAMP NULL,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                )
            `);

            // Добавляем индекс для быстрого поиска
            await connection.execute(`
                CREATE INDEX IF NOT EXISTS idx_passwords_user_id 
                ON passwords(user_id, deleted_at)
            `);

            res.json({ success: true, message: 'Database initialized' });
        } finally {
            connection.release();
        }
    } catch (error) {
        console.error('DB init error:', error);
        res.status(500).json({ success: false, message: error.message });
    }
});

// Отладочный маршрут для проверки таблиц
app.get('/api/debug-tables', async (req, res) => {
    try {
        const connection = await pool.getConnection();
        try {
            const [tables] = await connection.execute('SHOW TABLES');
            const tableNames = tables.map(t => Object.values(t)[0]);

            const tableData = {};
            for (const tableName of tableNames) {
                const [rows] = await connection.execute(`SELECT * FROM ${tableName} LIMIT 5`);
                tableData[tableName] = rows;
            }

            res.json({
                success: true,
                tables: tableNames,
                data: tableData
            });
        } finally {
            connection.release();
        }
    } catch (error) {
        console.error('Debug error:', error);
        res.status(500).json({ success: false, message: error.message });
    }
});

// Отдаем index.html для всех остальных маршрутов
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// Запускаем сервер
app.listen(PORT, () => {
    console.log(`✅ Server running on http://localhost:${PORT}`);
    console.log(`📊 Initialize database: http://localhost:${PORT}/api/init-db`);
    console.log(`🔐 Test auth endpoint: http://localhost:${PORT}/api/auth`);
    console.log(`🐛 Debug tables: http://localhost:${PORT}/api/debug-tables`);
});