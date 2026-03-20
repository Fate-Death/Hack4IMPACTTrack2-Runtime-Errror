const Database = require('better-sqlite3');
const path = require('path');

// Use a file-based SQLite database so it persists across restarts
const db = new Database(path.join(__dirname, 'webshield.db'));

// Enable WAL mode for better performance
db.pragma('journal_mode = WAL');

// Create users table
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    email TEXT,
    role TEXT DEFAULT 'user'
  )
`);

// Create comments table for XSS demo
db.exec(`
  CREATE TABLE IF NOT EXISTS comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    author TEXT NOT NULL,
    content TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )
`);

// Seed sample users (only if table is empty)
const userCount = db.prepare('SELECT COUNT(*) as count FROM users').get();
if (userCount.count === 0) {
  const insertUser = db.prepare('INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)');
  const seedUsers = [
    ['admin', 'password123', 'admin@webshield.ai', 'admin'],
    ['user1', 'mypassword', 'user1@example.com', 'user'],
    ['john_doe', 'john2024', 'john@example.com', 'user'],
    ['jane_smith', 'securepass', 'jane@example.com', 'moderator'],
  ];

  const insertMany = db.transaction((users) => {
    for (const user of users) {
      insertUser.run(...user);
    }
  });

  insertMany(seedUsers);
  console.log('✅ Database seeded with sample users');
}

// Seed sample comments
const commentCount = db.prepare('SELECT COUNT(*) as count FROM comments').get();
if (commentCount.count === 0) {
  const insertComment = db.prepare('INSERT INTO comments (author, content) VALUES (?, ?)');
  const seedComments = [
    ['admin', 'Welcome to WebShield AI! This platform demonstrates web security concepts.'],
    ['john_doe', 'Great tool for learning about SQL injection and XSS!'],
  ];

  const insertMany = db.transaction((comments) => {
    for (const comment of comments) {
      insertComment.run(...comment);
    }
  });

  insertMany(seedComments);
  console.log('✅ Database seeded with sample comments');
}

module.exports = db;
