# 🛡️ WebShield AI — Intelligent Web Security Testing Platform

An interactive web application that **demonstrates, detects, and prevents** common web vulnerabilities (SQL Injection & XSS) with AI-assisted input analysis.

![Built with](https://img.shields.io/badge/React-18-61dafb?style=flat-square&logo=react)
![Backend](https://img.shields.io/badge/Express-4.x-000000?style=flat-square&logo=express)
![Database](https://img.shields.io/badge/SQLite-3-003B57?style=flat-square&logo=sqlite)
![Security](https://img.shields.io/badge/Security-Educational-red?style=flat-square)

---

## 🎯 What It Does

| Feature | Description |
|---------|-------------|
| **SQL Injection Simulation** | Demonstrates login bypass using string concatenation vs parameterized queries |
| **XSS Attack Simulation** | Shows script injection vulnerability vs HTML escaping |
| **AI-Assisted Detection** | Pattern-based analysis with risk scoring (0–100) and classification |
| **Vulnerable vs Secure Mode** | Toggle to compare exploitable code with secure implementations |
| **Query Visualization** | Side-by-side view of vulnerable vs secure queries |
| **Prevention Suggestions** | Actionable remediation tips for each detected vulnerability |
| **C Module** | Optional native pattern detection module for high-performance analysis |

---

## 📁 Project Structure

```
sdis/
├── backend/
│   ├── server.js              # Express server + API routes
│   ├── db.js                  # SQLite database setup + seed data
│   ├── aiDetector.js          # AI detection module (pattern analysis)
│   ├── c_module/
│   │   ├── pattern_detect.c   # C-based pattern detection
│   │   └── Makefile
│   └── package.json
├── frontend/
│   ├── src/
│   │   ├── App.jsx            # Main app component
│   │   ├── App.css            # Premium dark glassmorphism theme
│   │   └── components/
│   │       ├── SqlInjectionPanel.jsx
│   │       ├── XssPanel.jsx
│   │       ├── ResultsDisplay.jsx
│   │       └── QueryVisualization.jsx
│   ├── index.html
│   ├── vite.config.js
│   └── package.json
└── README.md
```

---

## 🚀 Setup & Run

### Prerequisites
- **Node.js** 18+ and **npm**
- **gcc** (optional, for C module)

### 1. Install Dependencies

```bash
# Backend
cd backend
npm install

# Frontend
cd ../frontend
npm install
```

### 2. Compile C Module (Optional)

```bash
cd backend/c_module
make
make test   # runs test cases
```

### 3. Start the Application

**Terminal 1 — Backend (port 3001):**
```bash
cd backend
npm start
```

**Terminal 2 — Frontend (port 5173):**
```bash
cd frontend
npm run dev
```

**Open:** [http://localhost:5173](http://localhost:5173)

---

## 🧪 How to Test

### SQL Injection
1. Toggle to **Vulnerable Mode**
2. In the SQL Injection tab, click a preset like `' OR 1=1 --`
3. Click **Test Attack** → observe: all users returned, risk score: High
4. Toggle to **Secure Mode**, same input → attack is blocked

### XSS Attack
1. Toggle to **Vulnerable Mode**
2. In the XSS tab, click `<script>alert()` preset
3. Click **Test Attack** → raw HTML returned, risk score: High
4. Toggle to **Secure Mode** → HTML entities escaped safely

---

## 🏗️ Architecture

```
User Input → Frontend (React) → API Request → Backend (Express)
                                                   │
                                    ┌──────────────┼──────────────┐
                                    ▼              ▼              ▼
                              AI Detector     SQLite DB     C Module
                              (patterns,      (users,       (optional
                               scoring)       comments)     native scan)
                                    │              │              │
                                    └──────────────┼──────────────┘
                                                   ▼
                                           JSON Response
                                                   ▼
                                    Frontend renders results
                                    (risk score, classification,
                                     query visualization, suggestions)
```

---

## 🔌 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/sql-injection` | SQL injection simulation (accepts `username`, `password`, `mode`) |
| `POST` | `/api/xss` | XSS simulation (accepts `comment`, `mode`) |
| `POST` | `/api/analyze` | Standalone AI input analysis |
| `GET` | `/api/users` | List sample users |
| `GET` | `/api/health` | Health check |

---

## ⚠️ Disclaimer

This project is built for **educational and hackathon purposes only**. The vulnerable endpoints intentionally contain security flaws for demonstration. **Never deploy this in production** or use these techniques against systems without authorization.

---

## 🛠️ Tech Stack

- **Frontend:** React 18, Vite, Vanilla CSS (glassmorphism)
- **Backend:** Node.js, Express, better-sqlite3
- **AI Module:** Custom pattern matching engine (JavaScript)
- **C Module:** Native pattern detection via stdin/stdout
- **Database:** SQLite (file-based)
