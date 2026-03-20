function QueryVisualization({ results }) {
  if (!results) return null

  const isSQL = results.type === 'sql'

  return (
    <div className="card">
      <div className="query-viz">
        <div className="query-viz__title">
          <span>🔎</span>
          {isSQL ? 'Query Visualization' : 'Output Comparison'}
        </div>

        <div className="query-viz__blocks">
          {/* Actual Query / Output */}
          <div className="query-viz__block">
            <div className={`query-viz__block-label ${results.attackWorked ? 'query-viz__block-label--vulnerable' : 'query-viz__block-label--secure'}`}>
              {results.attackWorked ? '⚠️ ' : '✅ '}
              {results.queryType || results.outputType || 'Output'}
            </div>
            <pre className="query-viz__code">
              {isSQL ? results.query : results.renderedContent}
            </pre>
          </div>

          {/* Secure comparison */}
          {isSQL && (
            <div className="query-viz__block">
              <div className="query-viz__block-label query-viz__block-label--secure">
                ✅ Secure Alternative (Parameterized Query)
              </div>
              <pre className="query-viz__code">
                {`SELECT * FROM users WHERE username = ? AND password = ?\n-- Parameters are bound separately, preventing injection`}
              </pre>
            </div>
          )}

          {/* XSS: Show sanitized vs raw */}
          {!isSQL && results.sanitizedInput && (
            <div className="query-viz__block">
              <div className="query-viz__block-label query-viz__block-label--secure">
                ✅ Sanitized Output (HTML Escaped)
              </div>
              <pre className="query-viz__code">
                {results.sanitizedInput}
              </pre>
            </div>
          )}

          {!isSQL && results.originalInput && results.originalInput !== results.renderedContent && (
            <div className="query-viz__block">
              <div className="query-viz__block-label query-viz__block-label--vulnerable">
                ⚠️ Original Input (Raw)
              </div>
              <pre className="query-viz__code">
                {results.originalInput}
              </pre>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

export default QueryVisualization
