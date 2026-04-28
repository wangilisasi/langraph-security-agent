import { NavLink, Outlet } from 'react-router-dom'

export function Layout() {
  return (
    <>
      <div className="atmosphere" aria-hidden />
      <a className="skip-link" href="#main">
        Skip to main content
      </a>
      <div className="page">
        <header className="site-header">
          <div className="shell inner">
            <div className="brand">
              <NavLink to="/" className="brand-link">
                Injection Shield
              </NavLink>
              <span>Research API · ML + LangGraph</span>
            </div>
            <nav className="header-nav" aria-label="App navigation">
              <NavLink to="/monitoring" className={({ isActive }) => (isActive ? 'active' : undefined)}>
                Stats UI
              </NavLink>
              <NavLink to="/audit" className={({ isActive }) => (isActive ? 'active' : undefined)}>
                Incidents UI
              </NavLink>
              <a href="/docs">Swagger</a>
              <a href="/redoc">ReDoc</a>
              <a href="/health" target="_blank" rel="noreferrer">
                Health JSON
              </a>
            </nav>
          </div>
        </header>

        <main className="site-main" id="main">
          <div className="content">
            <Outlet />
          </div>
        </main>

        <footer className="site-footer">
          <div className="shell inner">
            <p className="footer-meta">Injection Shield · HTTP injection research</p>
            <ul className="footer-links" aria-label="Footer">
              <li>
                <a href="/docs">OpenAPI</a>
              </li>
              <li>
                <a href="/health">Health</a>
              </li>
              <li>
                <a href="/ip/127.0.0.1">Sample IP JSON</a>
              </li>
            </ul>
          </div>
        </footer>
      </div>
    </>
  )
}
