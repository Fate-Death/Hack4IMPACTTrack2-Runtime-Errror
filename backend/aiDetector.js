/**
 * WebShield AI — AI-Assisted Detection Module
 * 
 * Analyzes user input for SQL Injection and XSS patterns.
 * Returns classification, risk score, explanation, and prevention suggestions.
 */

// ─── Pattern Definitions ───────────────────────────────────────────────────────

const SQL_PATTERNS = [
  { regex: /'\s*OR\s+.+=.+/i,             weight: 30, name: "OR-based SQL Injection",     desc: "Tautology attack using OR clause to bypass authentication" },
  { regex: /'\s*OR\s+'[^']*'\s*=\s*'[^']*'/i, weight: 35, name: "String OR Injection",    desc: "String comparison tautology to always evaluate true" },
  { regex: /--/,                            weight: 20, name: "SQL Comment Injection",      desc: "Comment sequence (--) used to truncate the rest of the query" },
  { regex: /;\s*DROP\s+TABLE/i,            weight: 40, name: "DROP TABLE Attack",          desc: "Attempts to delete entire database tables" },
  { regex: /;\s*DELETE\s+FROM/i,           weight: 40, name: "DELETE Attack",              desc: "Attempts to delete records from database tables" },
  { regex: /UNION\s+SELECT/i,             weight: 35, name: "UNION SELECT Injection",     desc: "Extracts data from other tables by appending a UNION query" },
  { regex: /UNION\s+ALL\s+SELECT/i,       weight: 35, name: "UNION ALL SELECT",           desc: "Extracts data using UNION ALL to include duplicates" },
  { regex: /'\s*;\s*SELECT/i,             weight: 30, name: "Stacked Query Injection",    desc: "Executes additional SELECT query via statement stacking" },
  { regex: /SLEEP\s*\(/i,                 weight: 25, name: "Time-Based Blind SQLi",      desc: "Uses SLEEP() for time-based blind SQL injection" },
  { regex: /BENCHMARK\s*\(/i,             weight: 25, name: "Benchmark-Based Blind SQLi", desc: "Uses BENCHMARK() for performance-based blind injection" },
  { regex: /WAITFOR\s+DELAY/i,            weight: 25, name: "WAITFOR DELAY Attack",       desc: "MS SQL time delay for blind injection" },
  { regex: /'\s*AND\s+\d+=\d+/i,          weight: 20, name: "AND-based Injection",        desc: "Boolean-based blind injection using AND clause" },
  { regex: /ORDER\s+BY\s+\d+/i,           weight: 15, name: "ORDER BY Enumeration",       desc: "Column enumeration to determine table structure" },
  { regex: /INFORMATION_SCHEMA/i,          weight: 30, name: "Schema Enumeration",         desc: "Attempts to read database metadata/schema information" },
  { regex: /LOAD_FILE\s*\(/i,             weight: 35, name: "File Read Attack",           desc: "Attempts to read server files through SQL" },
  { regex: /INTO\s+(OUT|DUMP)FILE/i,       weight: 35, name: "File Write Attack",          desc: "Attempts to write files to the server filesystem" },
  { regex: /'\s*$/,                        weight: 10, name: "Trailing Quote",             desc: "Unmatched quote that may break SQL syntax" },
];

const XSS_PATTERNS = [
  { regex: /<script[\s>]/i,                weight: 40, name: "Script Tag Injection",       desc: "Injects JavaScript via <script> tags" },
  { regex: /<\/script>/i,                  weight: 30, name: "Script Close Tag",           desc: "Closing script tag found — likely part of script injection" },
  { regex: /on(error|load|click|mouseover|focus|blur|submit|change|input)\s*=/i,
                                            weight: 35, name: "Event Handler Injection",    desc: "Injects JavaScript via HTML event handler attributes" },
  { regex: /javascript\s*:/i,             weight: 35, name: "JavaScript URI Scheme",      desc: "Uses javascript: protocol to execute code" },
  { regex: /data\s*:\s*text\/html/i,       weight: 30, name: "Data URI HTML Injection",    desc: "Uses data: URI to inject HTML content" },
  { regex: /<iframe/i,                     weight: 30, name: "iFrame Injection",           desc: "Injects iframe to load external malicious content" },
  { regex: /<img[^>]+onerror/i,            weight: 35, name: "Image Error Handler",        desc: "Uses broken image with onerror handler to execute JS" },
  { regex: /<svg[^>]+onload/i,             weight: 35, name: "SVG Onload Injection",       desc: "Uses SVG element with onload handler to execute JS" },
  { regex: /<(embed|object|applet)/i,      weight: 30, name: "Embedded Object Injection",  desc: "Injects embedded objects that can execute code" },
  { regex: /eval\s*\(/i,                  weight: 25, name: "Eval Injection",             desc: "Uses eval() to execute arbitrary JavaScript" },
  { regex: /document\.(cookie|location|write)/i,
                                            weight: 30, name: "DOM Manipulation",           desc: "Accesses sensitive DOM properties (cookies, location, document.write)" },
  { regex: /window\.(location|open)/i,     weight: 25, name: "Window Manipulation",        desc: "Manipulates browser window (redirect, popup)" },
  { regex: /<\s*\w+[^>]*style\s*=\s*[^>]*expression\s*\(/i,
                                            weight: 30, name: "CSS Expression Attack",      desc: "Uses CSS expression() for JavaScript execution (IE)" },
  { regex: /alert\s*\(/i,                 weight: 15, name: "Alert Call",                 desc: "Calls alert() — common XSS proof of concept" },
  { regex: /<\s*body[^>]+onload/i,         weight: 30, name: "Body Onload Injection",      desc: "Injects onload handler on body element" },
];

// ─── Escape Function for HTML Sanitization ──────────────────────────────────────

function escapeHtml(str) {
  const map = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#x27;',
    '/': '&#x2F;',
  };
  return str.replace(/[&<>"'/]/g, (char) => map[char]);
}

// ─── Main Analysis Function ─────────────────────────────────────────────────────

function analyzeInput(input) {
  if (!input || typeof input !== 'string' || input.trim().length === 0) {
    return {
      classification: 'Safe',
      riskScore: 0,
      explanation: 'Input is empty or contains only whitespace.',
      detectedPatterns: [],
      preventionSuggestions: ['Always validate and sanitize user input.'],
      sanitizedInput: escapeHtml(input || ''),
    };
  }

  const detectedPatterns = [];
  let totalWeight = 0;

  // Check SQL injection patterns
  for (const pattern of SQL_PATTERNS) {
    if (pattern.regex.test(input)) {
      detectedPatterns.push({
        name: pattern.name,
        type: 'SQL Injection',
        description: pattern.desc,
        weight: pattern.weight,
      });
      totalWeight += pattern.weight;
    }
  }

  // Check XSS patterns
  for (const pattern of XSS_PATTERNS) {
    if (pattern.regex.test(input)) {
      detectedPatterns.push({
        name: pattern.name,
        type: 'XSS',
        description: pattern.desc,
        weight: pattern.weight,
      });
      totalWeight += pattern.weight;
    }
  }

  // Calculate risk score (capped at 100)
  const riskScore = Math.min(100, totalWeight);

  // Classify input
  let classification;
  if (riskScore === 0) {
    classification = 'Safe';
  } else if (riskScore <= 25) {
    classification = 'Suspicious';
  } else {
    classification = 'Malicious';
  }

  // Generate explanation
  let explanation;
  if (classification === 'Safe') {
    explanation = 'No known attack patterns detected in the input. The input appears to be safe for processing.';
  } else if (classification === 'Suspicious') {
    const types = [...new Set(detectedPatterns.map(p => p.type))];
    explanation = `Input contains patterns that resemble ${types.join(' and ')} techniques. While it may be legitimate, it should be treated with caution.`;
  } else {
    const types = [...new Set(detectedPatterns.map(p => p.type))];
    const topPattern = detectedPatterns.reduce((a, b) => a.weight > b.weight ? a : b);
    explanation = `⚠️ MALICIOUS INPUT DETECTED — Input contains ${detectedPatterns.length} attack pattern(s) matching ${types.join(' and ')} techniques. Primary threat: "${topPattern.name}" — ${topPattern.description}. This input could compromise application security if not properly handled.`;
  }

  // Generate prevention suggestions
  const preventionSuggestions = generatePreventionSuggestions(detectedPatterns);

  return {
    classification,
    riskScore,
    explanation,
    detectedPatterns,
    preventionSuggestions,
    sanitizedInput: escapeHtml(input),
  };
}

function generatePreventionSuggestions(patterns) {
  const suggestions = new Set();
  const types = new Set(patterns.map(p => p.type));

  // Always include these
  suggestions.add('Always validate and sanitize all user inputs on both client and server side.');

  if (types.has('SQL Injection')) {
    suggestions.add('Use parameterized queries (prepared statements) instead of string concatenation for SQL queries.');
    suggestions.add('Implement an allowlist of acceptable input characters for each field.');
    suggestions.add('Use an ORM (Object-Relational Mapping) library to abstract SQL queries.');
    suggestions.add('Apply the principle of least privilege to database accounts — avoid using admin/root credentials.');
    suggestions.add('Implement Web Application Firewall (WAF) rules to detect and block SQL injection attempts.');
  }

  if (types.has('XSS')) {
    suggestions.add('Escape all HTML special characters before rendering user input in the browser.');
    suggestions.add('Implement Content Security Policy (CSP) headers to restrict inline script execution.');
    suggestions.add('Use framework-provided auto-escaping (e.g., React\'s JSX, Angular\'s template binding).');
    suggestions.add('Set HttpOnly and Secure flags on cookies to prevent JavaScript access.');
    suggestions.add('Use a sanitization library like DOMPurify for any user-generated HTML content.');
  }

  if (types.size === 0) {
    suggestions.add('Implement input length limits appropriate for each field.');
    suggestions.add('Use strong Content Security Policy (CSP) headers.');
  }

  return [...suggestions];
}

module.exports = { analyzeInput, escapeHtml };
