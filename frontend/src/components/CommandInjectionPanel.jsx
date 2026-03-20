import { useState } from 'react'

const CMD_PRESETS = [
  { label: "127.0.0.1; ls", target: "127.0.0.1; ls -la" },
  { label: "8.8.8.8 && cat /etc/passwd", target: "8.8.8.8 && cat /etc/passwd" },
  { label: "google.com | id", target: "google.com | id" },
]

function CommandInjectionPanel({ onSubmit, loading, mode }) {
  const [target, setTarget] = useState('')

  const handleSubmit = (e) => {
    e.preventDefault()
    if (target.trim()) {
      onSubmit(target)
    }
  }

  return (
    <div className="card">
      <h2 className="card__title">
        <span className="card__title-icon">🖥️</span>
        Command Injection — OS Ping Utility
      </h2>

      <form onSubmit={handleSubmit}>
        <div className="form-group">
          <label className="form-group__label">Target IP / Hostname</label>
          <input
            className="form-group__input"
            type="text"
            placeholder="e.g. 127.0.0.1"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
          />
        </div>

        <div className="presets">
          <div className="presets__label">⚡ Quick Attack Payloads:</div>
          <div className="presets__list">
            {CMD_PRESETS.map((preset, i) => (
              <button
                key={i}
                type="button"
                className="presets__btn"
                onClick={() => setTarget(preset.target)}
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
            disabled={loading || !target.trim()}
          >
            {loading ? '' : mode === 'vulnerable' ? '⚡ Run Ping' : '🔒 Secure Ping'}
          </button>
        </div>
      </form>

      {mode === 'vulnerable' && (
        <div className="explanation" style={{ marginTop: '1rem' }}>
          <p className="explanation__text">
            <strong>⚠️ Vulnerable Mode:</strong> The backend passes the input directly to the OS standard shell. Try appending commands.
          </p>
        </div>
      )}
      {mode === 'secure' && (
        <div className="explanation" style={{ marginTop: '1rem' }}>
          <p className="explanation__text">
            <strong>🔒 Secure Mode:</strong> The backend strictly validates and strips malicious meta-characters before execution.
          </p>
        </div>
      )}
    </div>
  )
}

export default CommandInjectionPanel
