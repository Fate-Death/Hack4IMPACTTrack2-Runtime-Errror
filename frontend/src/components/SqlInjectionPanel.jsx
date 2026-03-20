import { useState } from 'react'

const SQL_PRESETS = [
  { label: "' OR 1=1 --", username: "' OR 1=1 --", password: "anything" },
  { label: "admin' --", username: "admin' --", password: "x" },
  { label: "' OR '1'='1", username: "' OR '1'='1", password: "' OR '1'='1" },
  { label: "' UNION SELECT", username: "' UNION SELECT * FROM users --", password: "x" },
  { label: "'; DROP TABLE", username: "'; DROP TABLE users; --", password: "x" },
]

function SqlInjectionPanel({ onSubmit, loading, mode }) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')

  const handlePreset = (preset) => {
    setUsername(preset.username)
    setPassword(preset.password)
  }

  const handleSubmit = (e) => {
    e.preventDefault()
    if (username.trim() && password.trim()) {
      onSubmit(username, password)
    }
  }

  return (
    <div className="card">
      <h2 className="card__title">
        <span className="card__title-icon">🗄️</span>
        SQL Injection — Login Bypass Simulation
      </h2>

      <form onSubmit={handleSubmit}>
        <div className="form-group">
          <label className="form-group__label" htmlFor="sql-username">Username</label>
          <input
            id="sql-username"
            className="form-group__input"
            type="text"
            placeholder="Enter username (try a SQL injection payload)"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
          />
        </div>

        <div className="form-group">
          <label className="form-group__label" htmlFor="sql-password">Password</label>
          <input
            id="sql-password"
            className="form-group__input"
            type="text"
            placeholder="Enter password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
        </div>

        {/* Attack Presets */}
        <div className="presets">
          <div className="presets__label">⚡ Quick Attack Payloads:</div>
          <div className="presets__list">
            {SQL_PRESETS.map((preset, i) => (
              <button
                key={i}
                type="button"
                className="presets__btn"
                onClick={() => handlePreset(preset)}
              >
                {preset.label}
              </button>
            ))}
          </div>
        </div>

        <div className="submit-area">
          <button
            type="submit"
            className={`btn ${mode === 'vulnerable' ? 'btn--danger' : 'btn--primary'} ${loading ? 'btn--loading' : ''}`}
            disabled={loading || !username.trim() || !password.trim()}
          >
            {loading ? '' : mode === 'vulnerable' ? '⚡ Test Attack' : '🔒 Test Secure'}
          </button>
          <button
            type="button"
            className="btn btn--ghost"
            onClick={() => { setUsername(''); setPassword(''); }}
          >
            Clear
          </button>
        </div>
      </form>

      {/* Info for Vulnerable Mode */}
      {mode === 'vulnerable' && (
        <div className="explanation" style={{ marginTop: '1rem' }}>
          <p className="explanation__text">
            <strong>⚠️ Vulnerable Mode:</strong> The backend builds SQL queries using string concatenation.
            Try entering SQL injection payloads above to bypass authentication and see all users.
          </p>
        </div>
      )}
      {mode === 'secure' && (
        <div className="explanation" style={{ marginTop: '1rem' }}>
          <p className="explanation__text">
            <strong>🔒 Secure Mode:</strong> The backend uses parameterized queries (prepared statements).
            SQL injection payloads are treated as literal strings, preventing code injection.
          </p>
        </div>
      )}
    </div>
  )
}

export default SqlInjectionPanel
