import { useState } from 'react'

const XSS_PRESETS = [
  { label: '<script>alert()', payload: "<script>alert('XSS')</script>" },
  { label: '<img onerror>', payload: '<img src=x onerror="alert(\'XSS\')">' },
  { label: '<svg onload>', payload: '<svg onload="alert(\'XSS\')">' },
  { label: 'javascript:', payload: '<a href="javascript:alert(\'XSS\')">Click me</a>' },
  { label: 'document.cookie', payload: '<script>document.cookie</script>' },
  { label: '<body onload>', payload: '<body onload="alert(\'XSS\')">' },
]

function XssPanel({ onSubmit, loading, mode }) {
  const [comment, setComment] = useState('')

  const handlePreset = (preset) => {
    setComment(preset.payload)
  }

  const handleSubmit = (e) => {
    e.preventDefault()
    if (comment.trim()) {
      onSubmit(comment)
    }
  }

  return (
    <div className="card">
      <h2 className="card__title">
        <span className="card__title-icon">📜</span>
        XSS Attack — Script Injection Simulation
      </h2>

      <form onSubmit={handleSubmit}>
        <div className="form-group">
          <label className="form-group__label" htmlFor="xss-comment">Comment / Input</label>
          <textarea
            id="xss-comment"
            className="form-group__textarea"
            placeholder="Enter a comment (try injecting HTML/JavaScript)"
            value={comment}
            onChange={(e) => setComment(e.target.value)}
          />
        </div>

        {/* Attack Presets */}
        <div className="presets">
          <div className="presets__label">⚡ Quick XSS Payloads:</div>
          <div className="presets__list">
            {XSS_PRESETS.map((preset, i) => (
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
            disabled={loading || !comment.trim()}
          >
            {loading ? '' : mode === 'vulnerable' ? '⚡ Test Attack' : '🔒 Test Secure'}
          </button>
          <button
            type="button"
            className="btn btn--ghost"
            onClick={() => setComment('')}
          >
            Clear
          </button>
        </div>
      </form>

      {mode === 'vulnerable' && (
        <div className="explanation" style={{ marginTop: '1rem' }}>
          <p className="explanation__text">
            <strong>⚠️ Vulnerable Mode:</strong> The backend returns user input as raw HTML without sanitization.
            Injected scripts and HTML elements will be rendered as-is.
          </p>
        </div>
      )}
      {mode === 'secure' && (
        <div className="explanation" style={{ marginTop: '1rem' }}>
          <p className="explanation__text">
            <strong>🔒 Secure Mode:</strong> The backend escapes HTML special characters before rendering.
            Scripts and HTML tags are converted to harmless text entities.
          </p>
        </div>
      )}
    </div>
  )
}

export default XssPanel
