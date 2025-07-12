const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const http = require('http');
const { Server } = require('socket.io');

const app = express();
const PORT = process.env.PORT || 5000;

const JWT_SECRET = process.env.JWT_SECRET || 'your_super_secret_jwt_key_please_change_this_in_production!';

const server = http.createServer(app);
const io = new Server(server, {
    cors: {
      origin: "http://localhost:5000",
      methods: ["GET", "POST"]
    }
  });

// --- Database Setup ---
const dbPath = path.resolve(__dirname, 'smallsteps.db');
const db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
        console.error('Error opening database:', err.message);
    } else {
        console.log('Connected to the SQLite database.');
        db.run(`CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fullName TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            passwordHash TEXT NOT NULL,
            role TEXT NOT NULL
        )`, (err) => {
            if (err) {
                console.error('Error creating users table:', err.message);
            } else {
                console.log('Users table checked/created.');
                db.get(`SELECT COUNT(*) AS count FROM users WHERE role = 'admin'`, (err, row) => {
                     if (row && row.count === 0) {
                         bcrypt.hash('adminpassword', 10).then(hash => {
                             db.run(`INSERT INTO users (fullName, email, passwordHash, role) VALUES (?, ?, ?, ?)`,
                                 ['Admin User', 'admin@example.com', hash, 'admin'],
                                 (err) => {
                                     if (err) console.error('Error inserting admin user:', err.message);
                                     else console.log('Default admin user created.');
                                 });
                         });
                       }
                 });
            }
        });

        db.run(`CREATE TABLE IF NOT EXISTS land_listings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            landownerId INTEGER NOT NULL,
            title TEXT NOT NULL,
            description TEXT,
            location TEXT NOT NULL,
            sizeAcres REAL NOT NULL,
            rentPerMonth REAL NOT NULL,
            availableDate TEXT,
            contactEmail TEXT NOT NULL,
            status TEXT DEFAULT 'available',
            createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
            updatedAt DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (landownerId) REFERENCES users(id) ON DELETE CASCADE
        )`, (err) => {
            if (err) {
                console.error('Error creating land_listings table:', err.message);
            } else {
                console.log('Land listings table checked/created.');
            }
        });

        db.run(`CREATE TABLE IF NOT EXISTS chat_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            userId INTEGER NOT NULL,
            userName TEXT NOT NULL,
            userRole TEXT NOT NULL,
            message TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            targetUserId INTEGER,
            FOREIGN KEY (userId) REFERENCES users(id) ON DELETE CASCADE
        )`, (err) => {
            if (err) {
                console.error('Error creating chat_messages table:', err.message);
            } else {
                console.log('Chat messages table checked/created.');
            }
        });
    }
});

// --- Middleware ---
app.use(cors());
app.use(bodyParser.json());

// NEW: Serve static files from the 'public' directory
app.use(express.static(path.join(__dirname, 'public')));

// JWT Authentication Middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (token == null) {
        console.log("Authentication: No token provided.");
        return res.status(401).json({ error: 'Authentication token required.' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            console.log("Authentication: Token verification failed.", err.message);
            return res.status(403).json({ error: 'Invalid or expired token.' });
        }
        req.user = user;
        next();
    });
};

const authorizeRole = (requiredRole) => (req, res, next) => {
    if (!req.user || req.user.role !== requiredRole) {
        console.log(`Authorization: Access denied. User role '${req.user ? req.user.role : 'None'}' does not match required role '${requiredRole}'.`);
        return res.status(403).json({ error: `Access denied. You do not have the required role (${requiredRole}).` });
    }
    next();
};

// API Endpoints
app.post('/api/signup', async (req, res) => {
    const { fullName, email, password, role } = req.body;

    if (!fullName || !email || !password || !role) {
        return res.status(400).json({ error: 'All fields are required.' });
    }
    if (password.length < 6) {
        return res.status(400).json({ error: 'Password must be at least 6 characters long.' });
    }
    const validRoles = ['landowner', 'tenant', 'admin'];
    if (!validRoles.includes(role)) {
        return res.status(400).json({ error: 'Invalid role specified.' });
    }

    try {
        db.get('SELECT * FROM users WHERE email = ? AND role = ?', [email, role], async (err, row) => {
            if (err) {
                console.error('DB error during signup (check existence):', err.message);
                return res.status(500).json({ error: 'Database error during signup.' });
            }
            if (row) {
                return res.status(409).json({ error: `A user with this email and role (${role}) already exists.` });
            }

            const passwordHash = await bcrypt.hash(password, 10);

            db.run('INSERT INTO users (fullName, email, passwordHash, role) VALUES (?, ?, ?, ?)',
                [fullName, email, passwordHash, role],
                function (err) {
                    if (err) {
                        console.error('Error inserting user into database:', err.message);
                        return res.status(500).json({ error: 'Error inserting user into database.' });
                    }
                    res.status(201).json({ success: true, message: 'User registered successfully!' });
                }
            );
        });
    } catch (error) {
        console.error('Signup process error:', error);
        res.status(500).json({ error: 'Server error during signup.' });
    }
});

app.post('/api/login', async (req, res) => {
    const { email, password, role } = req.body;

    if (!email || !password || !role) {
        return res.status(400).json({ error: 'Email, password, and role are required.' });
    }

    try {
        db.get('SELECT * FROM users WHERE email = ? AND role = ?', [email, role], async (err, user) => {
            if (err) {
                console.error('DB error during login (fetch user):', err.message);
                return res.status(500).json({ error: 'Database error during login.' });
            }
            if (!user) {
                return res.status(401).json({ error: 'Invalid email, password, or role combination.' });
            }

            const isMatch = await bcrypt.compare(password, user.passwordHash);

            if (!isMatch) {
                return res.status(401).json({ error: 'Invalid email, password, or role combination.' });
            }

            const token = jwt.sign(
                { id: user.id, email: user.email, role: user.role, fullName: user.fullName },
                JWT_SECRET,
                { expiresIn: '1h' }
            );

            res.status(200).json({
                token,
                user: {
                    id: user.id,
                    fullName: user.fullName,
                    email: user.email,
                    role: user.role
                }
            });
        });
    } catch (error) {
        console.error('Login process error:', error);
        res.status(500).json({ error: 'Server error during login.' });
    }
});

app.post('/api/landlistings', authenticateToken, authorizeRole('landowner'), async (req, res) => {
    const { title, description, location, sizeAcres, rentPerMonth, availableDate } = req.body;
    const landownerId = req.user.id;
    const contactEmail = req.user.email;

    if (!title || !location || !sizeAcres || !rentPerMonth) {
        return res.status(400).json({ error: 'Title, location, size (acres), and rent are required fields.' });
    }
    if (isNaN(parseFloat(sizeAcres)) || parseFloat(sizeAcres) <= 0) {
        return res.status(400).json({ error: 'Size (acres) must be a positive number.' });
    }
    if (isNaN(parseFloat(rentPerMonth)) || parseFloat(rentPerMonth) <= 0) {
        return res.status(400).json({ error: 'Rent per month must be a positive number.' });
    }

    db.run(
        `INSERT INTO land_listings (landownerId, title, description, location, sizeAcres, rentPerMonth, availableDate, contactEmail)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        [landownerId, title, description, location, sizeAcres, rentPerMonth, availableDate, contactEmail],
        function (err) {
            if (err) {
                console.error('Error adding land listing to database:', err.message);
                return res.status(500).json({ error: 'Failed to add land listing.' });
            }
            res.status(201).json({ success: true, message: 'Land listing added successfully!', listingId: this.lastID });
        }
    );
});

app.get('/api/landlistings/all', authenticateToken, authorizeRole('tenant'), (req, res) => {
    db.all(`SELECT * FROM land_listings WHERE status = 'available' ORDER BY createdAt DESC`, (err, rows) => {
        if (err) {
            console.error('Error fetching all land listings:', err.message);
            return res.status(500).json({ error: 'Failed to fetch land listings.' });
        }
        res.status(200).json(rows);
    });
});

app.get('/api/landlistings/mine', authenticateToken, authorizeRole('landowner'), (req, res) => {
    const landownerId = req.user.id;
    db.all(`SELECT * FROM land_listings WHERE landownerId = ? ORDER BY createdAt DESC`, [landownerId], (err, rows) => {
        if (err) {
            console.error('Error fetching landowner specific listings:', err.message);
            return res.status(500).json({ error: 'Failed to fetch your land listings.' });
        }
        res.status(200).json(rows);
    });
});

app.get('/api/chat/messages/all', authenticateToken, authorizeRole('admin'), (req, res) => {
    db.all(`SELECT
                cm.id,
                cm.userId,
                u.fullName AS userName,
                cm.userRole,
                cm.message,
                cm.timestamp,
                cm.targetUserId
            FROM chat_messages cm
            JOIN users u ON cm.userId = u.id
            ORDER BY cm.timestamp ASC`, (err, rows) => {
        if (err) {
            console.error('Error fetching all chat messages:', err.message);
            return res.status(500).json({ error: 'Failed to fetch chat messages.' });
        }
        res.status(200).json(rows);
    });
});

app.get('/api/chat/messages/my', authenticateToken, (req, res) => {
    const userId = req.user.id;
    const targetUserId = req.query.targetUserId;

    let sql = `SELECT
                id,
                userName,
                userRole,
                message,
                timestamp,
                targetUserId
            FROM chat_messages `;
    let params = [];

    if (req.user.role === 'admin' && targetUserId) {
        sql += `WHERE (userId = ? AND userRole != 'admin') OR (userId = ? AND userRole = 'admin' AND targetUserId = ?) `;
        params = [targetUserId, userId, targetUserId];
    } else {
        sql += `WHERE (userId = ?) OR (userRole = 'admin' AND targetUserId = ?) `;
        params = [userId, userId];
    }
    sql += `ORDER BY timestamp ASC`;

    db.all(sql, params, (err, rows) => {
        if (err) {
            console.error('Error fetching user-specific chat messages:', err.message);
            return res.status(500).json({ error: 'Failed to fetch your chat messages.' });
        }
        res.status(200).json(rows);
    });
});

// Socket.IO Real-time Chat Logic
io.on('connection', (socket) => {
    console.log('A user connected via WebSocket:', socket.id);

    const ADMIN_ROOM = 'admin_support_chat';

    socket.on('joinUserRoom', (userId) => {
        const userRoom = `user_${userId}`;
        socket.join(userRoom);
        console.log(`Socket ${socket.id} joined user room: ${userRoom}`);
    });

    socket.on('joinAdminRoom', () => {
        socket.join(ADMIN_ROOM);
        console.log(`Socket ${socket.id} joined admin room: ${ADMIN_ROOM}`);
    });

    socket.on('sendMessage', async (msgData) => {
        const { message, userId, userRole, userName, targetUserId } = msgData; 

        if (!message || !userId || !userRole || !userName) {
            console.warn('Received invalid message data:', msgData);
            return;
        }

        db.run(
            `INSERT INTO chat_messages (userId, userName, userRole, message, targetUserId) VALUES (?, ?, ?, ?, ?)`,
            [userId, userName, userRole, message, targetUserId || null],
            function (err) {
                if (err) {
                    console.error('Error saving chat message to database:', err.message);
                    socket.emit('messageError', 'Failed to save message.');
                    return;
                }
                const newMessage = {
                    id: this.lastID,
                    userId,
                    userName,
                    userRole,
                    message,
                    timestamp: new Date().toISOString(),
                    targetUserId: targetUserId || null 
                };

                if (userRole === 'admin' && targetUserId) {
                    const targetUserRoom = `user_${targetUserId}`;
                    io.to(targetUserRoom).emit('receiveMessage', newMessage);
                    io.to(ADMIN_ROOM).emit('receiveMessage', newMessage);
                    console.log(`Admin message from ${userName} (${userId}) to user ${targetUserId} broadcasted.`);
                } else {
                    const senderRoom = `user_${userId}`;
                    io.to(senderRoom).emit('receiveMessage', newMessage);
                    io.to(ADMIN_ROOM).emit('receiveMessage', newMessage);
                    console.log(`User message from ${userName} (${userId}) broadcasted.`);
                }
            }
        );
    });

    socket.on('disconnect', () => {
        console.log('A user disconnected from WebSocket:', socket.id);
    });
});

server.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
    console.log(`WebSocket server running on ws://localhost:${PORT}`);
});
