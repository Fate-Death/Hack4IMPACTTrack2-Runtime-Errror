import { useState } from 'react'
import SqlInjectionPanel from './components/SqlInjectionPanel'
import XssPanel from './components/XssPanel'
import ResultsDisplay from './components/ResultsDisplay'
import QueryVisualization from './components/QueryVisualization'

function App() {
  const [mode, setMode] = useState('vulnerable') // 'vulnerable' | 'secure'
  const [activeTab, setActiveTab] = useState('sql') // 'sql' | 'xss'
  const [results, setResults] = useState(null)
  const [loading, setLoading] = useState(false)

  const handleSqlSubmit = async (username, password) => {
    setLoading(true)
    setResults(null)
    try {
      const res = await fetch('/api/sql-injection', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password, mode }),
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
        body: JSON.stringify({ comment, mode }),
      })
      const data = await res.json()
      setResults({ type: 'xss', ...data })
    } catch (err) {
      setResults({ type: 'xss', error: true, message: 'Failed to connect to backend. Is the server running?' })
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
        <span className="mode-toggle__status">
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
      </div>

      {/* ─── Content Grid ────────────────────────────────────────────── */}
      <div className="content-grid">
        {/* Left: Input Panel */}
        <div className="content-grid__panel">
          {activeTab === 'sql' ? (
            <SqlInjectionPanel onSubmit={handleSqlSubmit} loading={loading} mode={mode} />
          ) : (
            <XssPanel onSubmit={handleXssSubmit} loading={loading} mode={mode} />
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
