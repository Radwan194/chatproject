const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const cors = require("cors");
const jwt = require("jsonwebtoken");

const SECRET_KEY = "my_name";
const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());

// Connect to SQLite database
const db = new sqlite3.Database("./chat.db", (err) => {
    if (err) console.error("Database connection error:", err.message);
    else console.log("Connected to SQLite database.");
});

// Create tables if they don't exist
db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        senderId TEXT NOT NULL,
        receiverId TEXT NOT NULL,
        message TEXT NOT NULL,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS friend_requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender TEXT NOT NULL,
        receiver TEXT NOT NULL,
        status TEXT DEFAULT 'Pending',
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS friends (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user1 TEXT NOT NULL,
        user2 TEXT NOT NULL
    )`);
});

// Middleware to verify JWT token
const authenticateToken = (req, res, next) => {
    const token = req.header("Authorization");
    if (!token) return res.status(401).json({ success: false, message: "Access denied. No token provided." });

    jwt.verify(token.split(" ")[1], SECRET_KEY, (err, user) => {
        if (err) return res.status(403).json({ success: false, message: "Invalid token." });
        req.user = user;
        next();
    });
};

// Routes
app.get("/", (req, res) => {
    res.send("Chat Server is running...");
});
app.get("/users", authenticateToken, (req, res) => {
    const query = `SELECT id, username FROM users`; // Exclude password for security

    db.all(query, [], (err, rows) => {
        if (err) {
            return res.status(500).json({ success: false, message: "Failed to retrieve users." });
        }
        res.json({ success: true, users: rows });
    });
});

// Login - Returns a token
app.post("/login", (req, res) => {
    const { username, password } = req.body;

    db.get(`SELECT * FROM users WHERE username = ? AND password = ?`, [username, password], (err, user) => {
        if (err || !user) return res.status(401).json({ success: false, message: "Invalid username or password." });

        const token = jwt.sign({ username: user.username }, SECRET_KEY, { expiresIn: "1h" });
        res.json({ success: true, message: "Login successful", token });
    });
});

// Register a new user
app.post("/add-user", (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ success: false, message: "Username and password required." });

    const query = `INSERT INTO users (username, password) VALUES (?, ?)`;
    db.run(query, [username, password], function (err) {
        if (err) return res.status(500).json({ success: false, message: "Error adding user." });
        res.json({ success: true, message: "User added successfully!", userId: this.lastID });
    });
});

// Send a message (Authenticated)
app.post("/send-message", authenticateToken, (req, res) => {
    const { senderId, receiverId, message } = req.body;

    if (!senderId || !receiverId || !message) {
        return res.status(400).json({ success: false, message: "All fields required." });
    }
    if (senderId === receiverId) {
        return res.status(400).json({ success: false, message: "Can't send to yourself." });
    }

    const query = `INSERT INTO messages (senderId, receiverId, message) VALUES (?, ?, ?)`;
    db.run(query, [senderId, receiverId, message], function (err) {
        if (err) {
            return res.status(500).json({ success: false, message: "Failed to send message." });
        }
        res.json({ success: true, message: "Message sent!", messageId: this.lastID });
    });
});

// Get messages between two users (Authenticated)
app.get("/messages", authenticateToken, (req, res) => {
    const { user1, user2 } = req.query;
    if (!user1 || !user2) {
        return res.status(400).json({ success: false, message: "Both users required." });
    }

    const query = `
        SELECT * FROM messages 
        WHERE (senderId = ? AND receiverId = ?) 
        OR (senderId = ? AND receiverId = ?)
        ORDER BY timestamp ASC
    `;

    db.all(query, [user1, user2, user2, user1], (err, rows) => {
        if (err) {
            return res.status(500).json({ success: false, message: "Failed to retrieve messages." });
        }
        res.json({ success: true, messages: rows });
    });
});

// Send friend request (Authenticated)
app.post("/send-friend-request", authenticateToken, async (req, res) => {
    const { sender, receiver } = req.body;

    if (!sender || !receiver || sender === receiver) {
        return res.status(400).json({ success: false, message: "Invalid request." });
    }

    try {
        // Check if they are already friends
        const queryFriend = `
    SELECT * FROM friends 
    WHERE (user1 = ? AND user2 = ?) OR (user1 = ? AND user2 = ?)`;
        const paramsFriend = [sender, receiver, receiver, sender];

        db.get(queryFriend, paramsFriend, (err, isFriend) => {
            if (err) {
                console.error("Error checking friends:", err);
                return res.status(500).json({ message: "Internal Server Error" });
            }

            if (isFriend) {
                console.log("DEBUG: Already friends.");
                return res.status(400).json({ success: false, message: "You are already friends with this user." });
            }

            const queryRequest = `
        SELECT sender, receiver FROM friend_requests 
        WHERE ((sender = ? AND receiver = ?) OR (sender = ? AND receiver = ?)) AND status="Pending"`;
            const paramsRequest = [sender, receiver, receiver, sender];

            db.all(queryRequest, paramsRequest, (err, rows) => {
                if (err) {
                    console.error("Error searching users:", err);
                    return res.status(500).json({ message: "Internal Server Error" });
                }

                if (rows.length > 0) {
                    console.log("DEBUG: Friend request already exists.");
                    return res.status(400).json({ success: false, message: "A friend request is already pending between you and this user." });
                }

                db.run(`INSERT INTO friend_requests (sender, receiver) VALUES (?, ?)`, [sender, receiver], (insertErr) => {
                    if (insertErr) {
                        console.error("Error inserting friend request:", insertErr);
                        return res.status(500).json({ message: "Internal Server Error" });
                    }

                    console.log("Friend request sent successfully.");
                    res.json({ success: true, message: "Friend request sent successfully." });
                });
            });
        });


    } catch (error) {
        console.error("Error sending friend request:", error);
        res.status(500).json({ success: false, message: "Server error." });
    }
});


// Respond to friend request (Authenticated)
app.post("/respond-friend-request", authenticateToken, (req, res) => {
    const { requestId, response } = req.body;
    if (!requestId || !["Accepted", "Rejected"].includes(response)) return res.status(400).json({ success: false, message: "Invalid request." });

    const query = `UPDATE friend_requests SET status = ? WHERE id = ?`;
    db.run(query, [response, requestId], function (err) {
        if (err) return res.status(500).json({ success: false, message: "Error updating request." });

        if (response === "Accepted") {
            const friendQuery = `INSERT INTO friends (user1, user2) SELECT sender, receiver FROM friend_requests WHERE id = ?`;
            db.run(friendQuery, [requestId]);
        }
        res.json({ success: true, message: `Friend request ${response.toLowerCase()}!` });
    });
});

// Get pending friend requests (Authenticated)
app.get("/friend-requests", authenticateToken, (req, res) => {
    const { user } = req.query;
    if (!user) return res.status(400).json({ success: false, message: "User required." });

    const query = `SELECT * FROM friend_requests WHERE receiver = ? AND status = 'Pending'`;
    db.all(query, [user], (err, rows) => {
        if (err) return res.status(500).json({ success: false, message: "Error fetching requests." });
        res.json({ success: true, friendRequests: rows });
    });
});

// Clear all data except users
app.delete("/clear-data", (req, res) => {
    const tables = ["messages", "friend_requests", "friends"];
    tables.forEach((table) => {
        db.run(`DELETE FROM ${table}`);
    });
    res.json({ success: true, message: "All non-user data deleted!" });
});

// Get friends list (Authenticated)
app.get("/friends", authenticateToken, (req, res) => {
    const { username } = req.query;
    if (!username) return res.status(400).json({ success: false, message: "Username required." });

    const query = `SELECT user1 AS friend FROM friends WHERE user2 = ? UNION SELECT user2 AS friend FROM friends WHERE user1 = ?`;
    db.all(query, [username, username], (err, rows) => {
        if (err) return res.status(500).json({ success: false, message: "Failed to retrieve friends." });
        res.json({ success: true, friends: rows.map(row => row.friend) });
    });
});
app.get("/search-users", (req, res) => {
    const { query, username } = req.query;

    if (!query || !username) {
        return res.status(400).json({ message: "Query and username are required" });
    }

    // Proper SQL query to fetch users except the requester
    const sql = `SELECT username FROM users WHERE username != ? AND username LIKE ?`;
    const params = [username, `%${query}%`];

    db.all(sql, params, (err, rows) => {
        if (err) {
            console.error("Error searching users:", err);
            return res.status(500).json({ message: "Internal Server Error" });
        }

        res.json(rows);
    });
});

app.get("/getuser", (req, res) => {
    const { username } = req.query;
    
    if (!username) {
        return res.status(400).json({ success: false, message: "Username is required." });
    }

    const query = `SELECT id FROM users WHERE username = ?`;
    
    db.get(query, [username], (err, row) => {
        if (err) {
            return res.status(500).json({ success: false, message: "Database error." });
        }

        if (!row) {
            return res.status(404).json({ success: false, message: "User not found." });
        }

        res.json({ success: true, userId: row.id });
    });
});
// Start server
app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
});
