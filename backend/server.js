const express = require('express');
const cors = require('cors');
const db = require('./db');
const { analyzeInput, escapeHtml } = require('./aiDetector');

const app = express();
const PORT = 3001;

// Middleware
app.use(cors());
app.use(express.json());

// ─── Health Check ───────────────────────────────────────────────────────────────

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// ─── SQL Injection Endpoint ─────────────────────────────────────────────────────

app.post('/api/sql-injection', (req, res) => {
  const { username, password, mode } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required.' });
  }

  // AI analysis on both inputs
  const usernameAnalysis = analyzeInput(username);
  const passwordAnalysis = analyzeInput(password);

  // Combine analyses — take the worse score
  const combinedRiskScore = Math.max(usernameAnalysis.riskScore, passwordAnalysis.riskScore);
  const combinedClassification = combinedRiskScore === 0 ? 'Safe'
    : combinedRiskScore <= 25 ? 'Suspicious' : 'Malicious';
  const allPatterns = [...usernameAnalysis.detectedPatterns, ...passwordAnalysis.detectedPatterns];
  const combinedExplanation = usernameAnalysis.riskScore >= passwordAnalysis.riskScore
    ? usernameAnalysis.explanation : passwordAnalysis.explanation;
  const combinedSuggestions = [...new Set([
    ...usernameAnalysis.preventionSuggestions,
    ...passwordAnalysis.preventionSuggestions,
  ])];

  let result;

  if (mode === 'vulnerable') {
    // ⚠️ VULNERABLE: String concatenation — DO NOT use in production!
    const vulnerableQuery = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;

    try {
      const stmt = db.prepare(vulnerableQuery);
      const rows = stmt.all();
      result = {
        success: true,
        attackWorked: rows.length > 0,
        query: vulnerableQuery,
        queryType: 'String Concatenation (VULNERABLE)',
        resultCount: rows.length,
        users: rows.map(u => ({ id: u.id, username: u.username, email: u.email, role: u.role })),
        message: rows.length > 0
          ? `🚨 Attack Successful! ${rows.length} user(s) returned. Attacker bypassed authentication!`
          : '✅ No users matched. Attack did not succeed with this input.',
      };
    } catch (err) {
      result = {
        success: false,
        attackWorked: false,
        query: vulnerableQuery,
        queryType: 'String Concatenation (VULNERABLE)',
        resultCount: 0,
        users: [],
        message: `SQL Error: ${err.message} — This error itself can leak database information to attackers.`,
        error: err.message,
      };
    }
  } else {
    // ✅ SECURE: Parameterized query
    const secureQuery = 'SELECT * FROM users WHERE username = ? AND password = ?';
    const displayQuery = `SELECT * FROM users WHERE username = ? AND password = ? -- Params: ['${escapeHtml(username)}', '${escapeHtml(password)}']`;

    try {
      const stmt = db.prepare(secureQuery);
      const rows = stmt.all(username, password);
      result = {
        success: true,
        attackWorked: false,
        query: displayQuery,
        queryType: 'Parameterized Query (SECURE)',
        resultCount: rows.length,
        users: rows.map(u => ({ id: u.id, username: u.username, email: u.email, role: u.role })),
        message: rows.length > 0
          ? `✅ Login successful for user "${rows[0].username}". Query executed securely with parameterized inputs.`
          : '✅ No matching user found. The parameterized query safely treated the input as literal data, not SQL code.',
      };
    } catch (err) {
      result = {
        success: false,
        attackWorked: false,
        query: displayQuery,
        queryType: 'Parameterized Query (SECURE)',
        resultCount: 0,
        users: [],
        message: `Query error: ${err.message}`,
        error: err.message,
      };
    }
  }

  res.json({
    ...result,
    analysis: {
      classification: combinedClassification,
      riskScore: combinedRiskScore,
      explanation: combinedExplanation,
      detectedPatterns: allPatterns,
      preventionSuggestions: combinedSuggestions,
    },
  });
});

// ─── XSS Endpoint ───────────────────────────────────────────────────────────────

app.post('/api/xss', (req, res) => {
  const { comment, mode } = req.body;

  if (!comment) {
    return res.status(400).json({ error: 'Comment is required.' });
  }

  const analysis = analyzeInput(comment);

  let result;

  if (mode === 'vulnerable') {
    // ⚠️ VULNERABLE: Raw HTML output — DO NOT use in production!
    result = {
      success: true,
      attackWorked: /<script|on\w+\s*=|javascript\s*:/i.test(comment),
      renderedContent: comment,  // Raw — no escaping!
      outputType: 'Raw HTML Output (VULNERABLE)',
      message: /<script|on\w+\s*=|javascript\s*:/i.test(comment)
        ? '🚨 XSS Attack Successful! The malicious script/handler will execute in the browser when rendered as HTML.'
        : '✅ No active XSS payload detected, but the input is still rendered without sanitization.',
      originalInput: comment,
    };
  } else {
    // ✅ SECURE: HTML-escaped output
    const sanitized = escapeHtml(comment);
    result = {
      success: true,
      attackWorked: false,
      renderedContent: sanitized,
      outputType: 'HTML-Escaped Output (SECURE)',
      message: '✅ Input has been HTML-escaped. All special characters are converted to their HTML entity equivalents, preventing script execution.',
      originalInput: comment,
      sanitizedInput: sanitized,
    };
  }

  res.json({
    ...result,
    analysis: {
      classification: analysis.classification,
      riskScore: analysis.riskScore,
      explanation: analysis.explanation,
      detectedPatterns: analysis.detectedPatterns,
      preventionSuggestions: analysis.preventionSuggestions,
    },
  });
});

// ─── Standalone Analysis Endpoint ───────────────────────────────────────────────

app.post('/api/analyze', (req, res) => {
  const { input } = req.body;

  if (!input) {
    return res.status(400).json({ error: 'Input is required.' });
  }

  const analysis = analyzeInput(input);
  res.json(analysis);
});

// ─── Get Sample Users (for demo) ────────────────────────────────────────────────

app.get('/api/users', (req, res) => {
  const users = db.prepare('SELECT id, username, email, role FROM users').all();
  res.json({ users });
});

// ─── Start Server ───────────────────────────────────────────────────────────────

app.listen(PORT, () => {
  console.log(`\n🛡️  WebShield AI Backend running on http://localhost:${PORT}`);
  console.log(`   ├─ POST /api/sql-injection  — SQL Injection simulation`);
  console.log(`   ├─ POST /api/xss            — XSS simulation`);
  console.log(`   ├─ POST /api/analyze         — Standalone AI analysis`);
  console.log(`   ├─ GET  /api/users           — List sample users`);
  console.log(`   └─ GET  /api/health          — Health check\n`);
});
