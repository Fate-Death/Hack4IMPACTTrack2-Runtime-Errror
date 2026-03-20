import { useState } from 'react'
import SqlInjectionPanel from './components/SqlInjectionPanel'
import XssPanel from './components/XssPanel'
import CommandInjectionPanel from './components/CommandInjectionPanel'
import ResultsDisplay from './components/ResultsDisplay'
import QueryVisualization from './components/QueryVisualization'

function App() {
  const [mode, setMode] = useState('vulnerable') // 'vulnerable' | 'secure'
  const [activeTab, setActiveTab] = useState('sql') // 'sql' | 'xss' | 'cmd'
  const [engine, setEngine] = useState('js') // 'js' | 'native'
  const [wafStrictness, setWafStrictness] = useState('off') // 'off' | 'strict'
  const [results, setResults] = useState(null)
  const [loading, setLoading] = useState(false)

  const handleSqlSubmit = async (username, password) => {
    setLoading(true)
    setResults(null)
    try {
      const res = await fetch('/api/sql-injection', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password, mode, engine, wafStrictness }),
      })
      const data = await res.json()
      setResults({ type: 'sql', ...data })
    } catch (err) {
      setResults({ type: 'sql', error: true, message: 'Failed to connect to backend. Is the server running?' })
    }
    setLoading(false)
  }

  const handleXssSubmit = async (comment) => {
    setLoading(true)
    setResults(null)
    try {
      const res = await fetch('/api/xss', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ comment, mode, engine, wafStrictness }),
      })
      const data = await res.json()
      setResults({ type: 'xss', ...data })
    } catch (err) {
      setResults({ type: 'xss', error: true, message: 'Failed to connect to backend. Is the server running?' })
    }
    setLoading(false)
  }

  const handleCmdSubmit = async (target) => {
    setLoading(true)
    setResults(null)
    try {
      const res = await fetch('/api/command-injection', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target, mode, engine, wafStrictness }),
      })
      const data = await res.json()
      setResults({ type: 'cmd', ...data })
    } catch (err) {
      setResults({ type: 'cmd', error: true, message: 'Failed to connect to backend. Is the server running?' })
    }
    setLoading(false)
  }

  return (
    <div className="app">
      {/* ─── Header ──────────────────────────────────────────────────── */}
      <header className="header">
        <div className="header__logo">
          <span className="header__shield">🛡️</span>
          <h1 className="header__title">WebShield AI</h1>
        </div>
        <p className="header__subtitle">
          Intelligent Web Security Testing Platform — Detect, Demonstrate & Prevent Web Vulnerabilities
        </p>
      </header>

      {/* ─── Mode Toggle ─────────────────────────────────────────────── */}
      <div className="mode-toggle">
        <div className="mode-toggle__container">
          <button
            className={`mode-toggle__btn mode-toggle__btn--vulnerable ${mode === 'vulnerable' ? 'active' : ''}`}
            onClick={() => setMode('vulnerable')}
          >
            ⚠️ Vulnerable Mode
          </button>
          <button
            className={`mode-toggle__btn mode-toggle__btn--secure ${mode === 'secure' ? 'active' : ''}`}
            onClick={() => setMode('secure')}
          >
            🔒 Secure Mode
          </button>
        </div>
        
        {/* New Advanced Controls */}
        <div className="advanced-controls" style={{ marginTop: '1rem', display: 'flex', gap: '2rem', justifyContent: 'center' }}>
          <div>
            <label style={{ marginRight: '0.5rem', fontWeight: 'bold' }}>AI Engine:</label>
            <select value={engine} onChange={(e) => setEngine(e.target.value)} style={{ padding: '0.35rem', borderRadius: '4px', background: 'var(--bg-lighter)', color: 'white', border: '1px solid var(--border)' }}>
              <option value="js">JavaScript (Regex)</option>
              <option value="native">C Module (Native High-Perf)</option>
            </select>
          </div>
          <div>
            <label style={{ marginRight: '0.5rem', fontWeight: 'bold' }}>WAF Strictness:</label>
            <select value={wafStrictness} onChange={(e) => setWafStrictness(e.target.value)} style={{ padding: '0.35rem', borderRadius: '4px', background: 'var(--bg-lighter)', color: 'white', border: '1px solid var(--border)' }}>
              <option value="off">Off</option>
              <option value="strict">Strict (High False Positives)</option>
            </select>
          </div>
        </div>

        <span className="mode-toggle__status" style={{ marginTop: '1rem', display: 'block' }}>
          {mode === 'vulnerable'
            ? '🔴 Protections OFF — Simulating real vulnerabilities'
            : '🟢 Protections ON — Using secure coding practices'}
        </span>
      </div>

      {/* ─── Tab Navigation ──────────────────────────────────────────── */}
      <div className="tabs">
        <button
          className={`tabs__btn ${activeTab === 'sql' ? 'active' : ''}`}
          onClick={() => { setActiveTab('sql'); setResults(null); }}
        >
          <span className="tabs__icon">🗄️</span>
          SQL Injection Testing
        </button>
        <button
          className={`tabs__btn ${activeTab === 'xss' ? 'active' : ''}`}
          onClick={() => { setActiveTab('xss'); setResults(null); }}
        >
          <span className="tabs__icon">📜</span>
          XSS Attack Testing
        </button>
        <button
          className={`tabs__btn ${activeTab === 'cmd' ? 'active' : ''}`}
          onClick={() => { setActiveTab('cmd'); setResults(null); }}
        >
          <span className="tabs__icon">🖥️</span>
          Command Injection
        </button>
      </div>

      {/* ─── Content Grid ────────────────────────────────────────────── */}
      <div className="content-grid">
        {/* Left: Input Panel */}
        <div className="content-grid__panel">
          {activeTab === 'sql' ? (
            <SqlInjectionPanel onSubmit={handleSqlSubmit} loading={loading} mode={mode} />
          ) : activeTab === 'xss' ? (
            <XssPanel onSubmit={handleXssSubmit} loading={loading} mode={mode} />
          ) : (
            <CommandInjectionPanel onSubmit={handleCmdSubmit} loading={loading} mode={mode} />
          )}
        </div>

        {/* Right: Results */}
        <div className="content-grid__panel">
          {results ? (
            <>
              <ResultsDisplay results={results} />
              {results.query && <QueryVisualization results={results} />}
            </>
          ) : (
            <div className="card">
              <div className="empty-state">
                <div className="empty-state__icon">🔍</div>
                <h3 className="empty-state__title">No Results Yet</h3>
                <p className="empty-state__desc">
                  Enter some input and click &quot;Test Attack&quot; to see the AI-powered vulnerability analysis.
                </p>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* ─── Footer ──────────────────────────────────────────────────── */}
      <footer className="footer">
        <p>🛡️ WebShield AI — Built for educational purposes only. Do not use against real systems without authorization.</p>
      </footer>
    </div>
  )
}

export default App
