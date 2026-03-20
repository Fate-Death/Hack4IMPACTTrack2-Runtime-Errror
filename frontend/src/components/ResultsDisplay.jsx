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
            <div className="xss-preview__content">
              {results.renderedContent}
            </div>
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
