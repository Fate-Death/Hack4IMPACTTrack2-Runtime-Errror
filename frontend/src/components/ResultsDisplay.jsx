function ResultsDisplay({ results }) {
  if (!results || results.error) {
    return (
      <div className="card">
        <div className="results__message" style={{ borderLeftColor: 'var(--accent-red)' }}>
          {results?.message || 'An error occurred. Please try again.'}
        </div>
      </div>
    )
  }

  const { analysis } = results
  const riskLevel = analysis?.riskScore === 0 ? 'safe'
    : analysis?.riskScore <= 25 ? 'suspicious' : 'malicious'

  return (
    <div className="results">
      {/* Attack Result Card */}
      <div className="card">
        <h2 className="card__title">
          <span className="card__title-icon">📊</span>
          Analysis Results
        </h2>

        {/* Attack Result Badge */}
        <div className="results__header">
          <span className={`results__badge ${results.attackWorked ? 'results__badge--success' : 'results__badge--blocked'}`}>
            {results.attackWorked ? '🚨 ATTACK SUCCEEDED' : '✅ ATTACK BLOCKED'}
          </span>
          {results.resultCount !== undefined && (
            <span className="results__badge results__badge--info">
              {results.resultCount} record(s) returned
            </span>
          )}
        </div>

        {/* Message */}
        <div className="results__message">
          {results.message}
        </div>

        {/* Risk Score */}
        {analysis && (
          <div className="risk-score">
            <div className="risk-score__header">
              <span className="risk-score__label">Risk Score</span>
              <span className={`risk-score__value risk-score__value--${riskLevel}`}>
                {analysis.riskScore}/100
              </span>
            </div>
            <div className="risk-score__bar">
              <div
                className={`risk-score__fill risk-score__fill--${riskLevel}`}
                style={{ width: `${analysis.riskScore}%` }}
              />
            </div>
          </div>
        )}

        {/* Classification */}
        {analysis && (
          <div className={`classification classification--${riskLevel}`}>
            <span className="classification__dot" />
            Input Classification: {analysis.classification}
            {analysis.source && (
              <span style={{ marginLeft: 'auto', fontSize: '0.8rem', opacity: 0.7, background: 'rgba(255,255,255,0.1)', padding: '2px 6px', borderRadius: '4px' }}>
                Engine: {analysis.source === 'native' ? 'C Native Module' : 'JavaScript Engine'}
              </span>
            )}
          </div>
        )}

        {/* LLM Explanation */}
        {analysis?.llmExplanation && (
          <div className="llm-card" style={{ background: 'var(--bg-lighter)', padding: '1rem', borderRadius: '8px', borderLeft: '4px solid #61dafb', margin: '1rem 0' }}>
            <h4 style={{ margin: '0 0 0.5rem 0', display: 'flex', alignItems: 'center', gap: '0.5rem', color: '#61dafb' }}>
              🤖 AI Code Assistant Summarizer
            </h4>
            <p style={{ margin: 0, fontSize: '0.95rem', lineHeight: '1.4', color: 'var(--text)' }}>
              {analysis.llmExplanation}
            </p>
          </div>
        )}

        {/* Explanation */}
        {analysis?.explanation && (
          <div className="explanation">
            <p className="explanation__text">{analysis.explanation}</p>
          </div>
        )}

        {/* Detected Patterns */}
        {analysis?.detectedPatterns?.length > 0 && (
          <div className="patterns">
            <div className="patterns__title">🎯 Detected Attack Patterns</div>
            <div className="patterns__list">
              {analysis.detectedPatterns.map((pattern, i) => (
                <div key={i} className="patterns__item">
                  <span className={`patterns__item-type ${pattern.type === 'SQL Injection' ? 'patterns__item-type--sql' : 'patterns__item-type--xss'}`}>
                    {pattern.type}
                  </span>
                  <div className="patterns__item-info">
                    <div className="patterns__item-name">{pattern.name}</div>
                    <div className="patterns__item-desc">{pattern.description}</div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Users Table (SQL Injection results) */}
        {results.users && results.users.length > 0 && (
          <div style={{ marginTop: '1rem' }}>
            <div className="patterns__title">👥 Exposed User Data</div>
            <table className="users-table">
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Username</th>
                  <th>Email</th>
                  <th>Role</th>
                </tr>
              </thead>
              <tbody>
                {results.users.map((user) => (
                  <tr key={user.id}>
                    <td>{user.id}</td>
                    <td>{user.username}</td>
                    <td>{user.email}</td>
                    <td>{user.role}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* XSS Rendered Output */}
        {results.type === 'xss' && results.renderedContent && (
          <div className="xss-preview">
            <div className="xss-preview__label">
              {results.outputType || 'Rendered Output'}
            </div>
            {results.attackWorked ? (
              <div className="xss-preview__content" style={{ border: '2px dashed #ff4444', padding: '1rem', background: 'rgba(255, 68, 68, 0.1)', overflow: 'hidden' }}>
                <p style={{ marginTop: 0, color: '#ff4444', fontSize: '0.8rem', fontWeight: 'bold' }}>⚠️ DANGER: Real execution sandbox</p>
                <iframe 
                  sandbox="allow-scripts" 
                  srcDoc={results.renderedContent} 
                  style={{ width: '100%', height: '50px', border: 'none', background: 'white' }}
                />
              </div>
            ) : (
              <div className="xss-preview__content">
                {results.renderedContent}
              </div>
            )}
          </div>
        )}

        {/* CMD Rendered Output */}
        {results.type === 'cmd' && results.output && (
          <div className="xss-preview">
            <div className="xss-preview__label">
              Terminal Output
            </div>
            <pre className="xss-preview__content" style={{ background: '#0d1117', color: '#00ff00', padding: '1rem', overflowX: 'auto', fontFamily: 'monospace', borderRadius: '6px' }}>
              {results.output}
            </pre>
          </div>
        )}

        {/* Prevention Suggestions */}
        {analysis?.preventionSuggestions?.length > 0 && (
          <div className="suggestions">
            <div className="suggestions__title">
              🛡️ Prevention Suggestions
            </div>
            <ul className="suggestions__list">
              {analysis.preventionSuggestions.map((suggestion, i) => (
                <li key={i} className="suggestions__item">{suggestion}</li>
              ))}
            </ul>
          </div>
        )}
      </div>
    </div>
  )
}

export default ResultsDisplay
