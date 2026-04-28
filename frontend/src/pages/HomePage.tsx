import { Link } from 'react-router-dom'

export function HomePage() {
  return (
    <div className="hero-animate">
      <p className="eyebrow">Tiered detection pipeline</p>
      <h1>Injection Shield</h1>
      <p className="tagline">HTTP injection detection, without the wait.</p>
      <p className="summary">
        Fast scoring on every request; uncertain traffic passes through instantly while LangGraph and an LLM
        reason about grey-zone cases in the background—incidents and IP reputation stay in SQLite for audit and
        research.
      </p>

      <nav className="links" aria-label="App and API shortcuts">
        <a href="/docs">
          <strong>Swagger UI</strong>
          <p>Explore and run the API interactively.</p>
        </a>
        <Link to="/monitoring" className="card-link">
          <strong>Detection stats</strong>
          <p>Incident counts and thresholds in the UI (JSON from <code>/stats</code>).</p>
        </Link>
        <Link to="/audit" className="card-link">
          <strong>Recent incidents</strong>
          <p>Browse decisions in the UI (JSON from <code>/incidents</code>).</p>
        </Link>
        <a href="/redoc">
          <strong>ReDoc</strong>
          <p>OpenAPI reference, reader-friendly layout.</p>
        </a>
      </nav>

      <p className="endpoint-hint">
        <code>POST /analyze</code> — submit a request. Grey-zone follow-up:{' '}
        <code>{'GET /request/{request_id}'}</code>
      </p>
    </div>
  )
}
