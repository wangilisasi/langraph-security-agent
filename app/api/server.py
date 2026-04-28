"""FastAPI server for the HTTP injection detection and response pipeline."""

import asyncio
import datetime
import logging
import threading
from contextlib import asynccontextmanager
from concurrent.futures import ThreadPoolExecutor

from fastapi import FastAPI, BackgroundTasks
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from app.detection.detector import (
    parse_http_request,
    predict,
    load_model,
    HIGH_THRESHOLD,
    LOW_THRESHOLD,
)
from app.graph.response_nodes import auto_respond, pass_through
from app.graph.security_agent import security_agent
from app.storage import database as db

logger = logging.getLogger("security_server")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

OPENAPI_DESCRIPTION = """
**Injection Shield** is a research API for HTTP-layer injection detection. It combines a
fast inline scorer with asynchronous LLM analysis for uncertain (grey-zone) traffic.

## `POST /analyze`

Submit a synthetic or captured HTTP request (`method`, `url`, `headers`, `body`, `source_ip`).
The service returns a **confidence** score, **tier** (high / low / grey / banned), and
**decision** / **action_taken**.

- **High confidence attack** — Handled immediately (block path; no user-visible LLM delay).
- **Low confidence** — Treated as benign for the fast path (log / pass-through behavior per your pipeline).
- **Grey zone** — The request is **passed through immediately**; a LangGraph + LLM workflow runs
  **in the background** to refine the decision, update incidents, and IP reputation.

Use **`GET /request/{request_id}`** with the `request_id` from the analyze response to poll
grey-zone processing status and the final incident record when available.

## Other endpoints

- **`GET /health`** — Liveness (no database work).
- **`GET /incidents`**, **`GET /stats`**, **`GET /ip/{source_ip}`** — Audit and reputation data (JSON).

Design notes for this project live in the repo (`ARCHITECTURE.md`). Source:
[github.com/wangilisasi/langraph-security-agent](https://github.com/wangilisasi/langraph-security-agent).
"""

# Thread pool for running the synchronous LangGraph agent in the background
_executor = ThreadPoolExecutor(max_workers=4)
_analysis_status_lock = threading.Lock()
_analysis_status: dict[str, dict] = {}


def _now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _set_analysis_status(request_id: str, status: str, **fields) -> None:
    with _analysis_status_lock:
        existing = _analysis_status.get(request_id, {})
        merged = {**existing, **fields}
        merged["status"] = status
        merged["updated_at"] = _now_iso()
        _analysis_status[request_id] = merged


def _get_analysis_status(request_id: str) -> dict | None:
    with _analysis_status_lock:
        status = _analysis_status.get(request_id)
        return dict(status) if status else None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup / shutdown hooks."""
    load_model()
    db.init_db()
    logger.info(
        "Security server started (HIGH=%.2f, LOW=%.2f)",
        HIGH_THRESHOLD, LOW_THRESHOLD,
    )
    yield
    _executor.shutdown(wait=False)
    logger.info("Security server stopped")


app = FastAPI(
    title="Injection Shield",
    description=OPENAPI_DESCRIPTION.strip(),
    version="0.1.0",
    lifespan=lifespan,
)


# ---------------------------------------------------------------------------
# Request / Response schemas
# ---------------------------------------------------------------------------

class AnalyzeRequest(BaseModel):
    method: str = Field(default="GET", examples=["GET", "POST", "PUT"])
    url: str = Field(examples=["/api/login"])
    headers: dict[str, str] = Field(default_factory=dict)
    body: str = Field(default="")
    source_ip: str = Field(examples=["192.168.1.100"])


class AnalyzeResponse(BaseModel):
    request_id: str
    confidence: float
    tier: str
    decision: str
    action_taken: str
    detail: str


# ---------------------------------------------------------------------------
# Grey-zone background processing
# ---------------------------------------------------------------------------

def _run_llm_analysis(http_request: dict, detection_result: dict) -> None:
    """Run the full LangGraph security agent for a grey-zone request.

    This runs synchronously in a thread pool — does not block the API response.
    """
    request_id = detection_result["request_id"]
    try:
        _set_analysis_status(request_id, "running")
        logger.info("LLM analysis started for %s", request_id)
        security_agent.invoke({
            "http_request": http_request,
            "detection_result": detection_result,
        })
        incident = db.get_incident_by_request_id(request_id)
        if incident:
            _set_analysis_status(
                request_id,
                "completed",
                completed_at=_now_iso(),
                decision=incident.get("decision"),
                action_taken=incident.get("action_taken"),
                decision_source=incident.get("decision_source"),
            )
        else:
            _set_analysis_status(request_id, "completed", completed_at=_now_iso())
        logger.info("LLM analysis completed for %s", request_id)
    except Exception as exc:
        _set_analysis_status(
            request_id,
            "failed",
            completed_at=_now_iso(),
            error=str(exc),
        )
        logger.exception("LLM analysis failed for %s", request_id)


async def queue_llm_analysis(http_request: dict, detection_result: dict) -> None:
    """Submit a grey-zone request to the thread pool for async LLM analysis."""
    loop = asyncio.get_event_loop()
    loop.run_in_executor(_executor, _run_llm_analysis, http_request, detection_result)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/health")
async def health():
    """Liveness probe for load balancers and monitoring (no DB or model work)."""
    return {"status": "ok", "version": app.version}


@app.get("/", response_class=HTMLResponse)
async def root():
    """Serve a small human-friendly overview page for the API root."""
    return """
    <!doctype html>
    <html lang="en">
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <meta name="description" content="Injection Shield — HTTP injection detection API: fast ML scoring, LangGraph grey-zone analysis, incidents and IP reputation.">
        <title>Injection Shield · API</title>
        <link rel="preconnect" href="https://fonts.googleapis.com">
        <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
        <link href="https://fonts.googleapis.com/css2?family=Fraunces:ital,opsz,wght@0,9..144,550;1,9..144,550&family=Lexend:wght@400;500;600&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
        <style>
          :root {
            color-scheme: light dark;
            --ink: #12141a;
            --ink-soft: #3d4350;
            --muted: #5c6475;
            --bg: #f3f1ec;
            --bg-deep: #e6e2d9;
            --surface: rgba(255, 255, 255, 0.78);
            --surface-solid: #fdfcfa;
            --border: rgba(18, 20, 26, 0.1);
            --accent: #0f6b5c;
            --accent-glow: rgba(15, 107, 92, 0.22);
            --warn: #b45309;
            --focus: #0d5c6e;
            --font-display: "Fraunces", "Iowan Old Style", "Palatino Linotype", Palatino, Georgia, serif;
            --font-ui: "Lexend", system-ui, sans-serif;
            --font-mono: "JetBrains Mono", ui-monospace, monospace;
            font-family: var(--font-ui);
            background-color: var(--bg);
            color: var(--ink);
          }

          * {
            box-sizing: border-box;
          }

          body {
            margin: 0;
            min-height: 100vh;
          }

          .atmosphere {
            position: fixed;
            inset: 0;
            z-index: -1;
            pointer-events: none;
            background:
              radial-gradient(1200px 700px at 12% -8%, var(--accent-glow), transparent 55%),
              radial-gradient(900px 500px at 88% 108%, rgba(180, 83, 9, 0.08), transparent 50%),
              linear-gradient(165deg, var(--bg) 0%, var(--bg-deep) 100%);
          }

          .atmosphere::after {
            content: "";
            position: absolute;
            inset: 0;
            opacity: 0.35;
            background-image: url("data:image/svg+xml,%3Csvg viewBox='0 0 256 256' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.85' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)' opacity='0.05'/%3E%3C/svg%3E");
          }

          .skip-link {
            position: absolute;
            left: 12px;
            top: 12px;
            padding: 8px 12px;
            background: var(--surface-solid);
            border: 1px solid var(--border);
            border-radius: 8px;
            font-size: 0.8125rem;
            font-family: var(--font-ui);
            color: var(--ink);
            text-decoration: none;
            z-index: 100;
            clip-path: inset(50%);
            width: 1px;
            height: 1px;
            overflow: hidden;
            white-space: nowrap;
          }

          .skip-link:focus {
            clip-path: none;
            width: auto;
            height: auto;
            overflow: visible;
          }

          .skip-link:focus-visible {
            outline: 2px solid var(--focus);
            outline-offset: 2px;
          }

          .page {
            min-height: 100vh;
            display: flex;
            flex-direction: column;
          }

          .shell {
            width: min(920px, 100%);
            margin-inline: auto;
            padding-inline: clamp(16px, 4vw, 28px);
          }

          .site-header {
            flex-shrink: 0;
            border-bottom: 1px solid var(--border);
            background: var(--surface);
            backdrop-filter: blur(14px);
            -webkit-backdrop-filter: blur(14px);
          }

          .site-header .inner {
            display: flex;
            flex-wrap: wrap;
            align-items: center;
            justify-content: space-between;
            gap: 14px 28px;
            padding-block: 18px;
          }

          .brand {
            font-family: var(--font-display);
            font-weight: 550;
            font-size: 1.2rem;
            letter-spacing: -0.03em;
            line-height: 1.15;
            color: var(--ink);
          }

          .brand span {
            display: block;
            font-family: var(--font-ui);
            font-weight: 400;
            font-size: 0.75rem;
            letter-spacing: 0.04em;
            text-transform: uppercase;
            color: var(--muted);
            margin-top: 6px;
          }

          .header-nav {
            display: flex;
            flex-wrap: wrap;
            gap: 6px;
          }

          .header-nav a {
            font-size: 0.8125rem;
            font-weight: 500;
            color: var(--ink-soft);
            text-decoration: none;
            padding: 8px 12px;
            border-radius: 999px;
            border: 1px solid transparent;
            transition: color 0.2s, background 0.2s, border-color 0.2s;
          }

          .header-nav a:hover {
            color: var(--accent);
            background: rgba(15, 107, 92, 0.08);
            border-color: rgba(15, 107, 92, 0.15);
          }

          .header-nav a:focus-visible {
            outline: 2px solid var(--focus);
            outline-offset: 2px;
          }

          @media (max-width: 640px) {
            .site-header .inner {
              flex-direction: column;
              align-items: stretch;
              gap: 10px;
              padding-block: 14px;
            }

            .brand {
              font-size: 1.05rem;
            }

            .brand span {
              font-size: 0.6875rem;
            }

            .header-nav {
              display: flex;
              flex-wrap: nowrap;
              overflow-x: auto;
              overflow-y: hidden;
              gap: 8px;
              padding: 4px 2px 10px;
              margin: 0 -6px;
              padding-left: 6px;
              padding-right: 6px;
              -webkit-overflow-scrolling: touch;
              scrollbar-width: thin;
            }

            .header-nav a {
              flex-shrink: 0;
              padding: 8px 14px;
              font-size: 0.78rem;
            }
          }

          .site-main {
            flex: 1;
            display: flex;
            align-items: center;
            justify-content: center;
            padding-block: clamp(36px, 8vw, 72px);
          }

          .site-main .content {
            width: min(920px, 100%);
            padding-inline: clamp(16px, 4vw, 28px);
          }

          @keyframes rise {
            from {
              opacity: 0;
              transform: translateY(16px);
            }
            to {
              opacity: 1;
              transform: translateY(0);
            }
          }

          .hero-animate > * {
            animation: rise 0.65s cubic-bezier(0.22, 1, 0.36, 1) backwards;
          }

          .hero-animate > *:nth-child(1) { animation-delay: 0.04s; }
          .hero-animate > *:nth-child(2) { animation-delay: 0.1s; }
          .hero-animate > *:nth-child(3) { animation-delay: 0.16s; }
          .hero-animate > *:nth-child(4) { animation-delay: 0.22s; }
          .hero-animate > *:nth-child(5) { animation-delay: 0.28s; }
          .hero-animate > *:nth-child(6) { animation-delay: 0.34s; }

          .eyebrow {
            font-size: 0.75rem;
            font-weight: 600;
            letter-spacing: 0.14em;
            text-transform: uppercase;
            color: var(--accent);
            margin-bottom: 14px;
          }

          h1 {
            font-family: var(--font-display);
            font-weight: 550;
            margin: 0 0 10px;
            font-size: clamp(2.15rem, 5.5vw, 3.35rem);
            line-height: 1.08;
            letter-spacing: -0.035em;
            color: var(--ink);
          }

          .tagline {
            font-family: var(--font-ui);
            font-size: clamp(1.05rem, 2.4vw, 1.3rem);
            font-weight: 500;
            color: var(--ink-soft);
            margin: 0 0 18px;
            max-width: 36rem;
            line-height: 1.4;
          }

          p {
            margin: 0;
            color: var(--muted);
            line-height: 1.65;
          }

          .summary {
            max-width: 38rem;
            font-size: 1.0625rem;
            color: var(--ink-soft);
          }

          .links {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(210px, 1fr));
            gap: 14px;
            margin-top: 32px;
          }

          .links a {
            --card-accent: var(--accent);
            display: block;
            min-height: 100px;
            padding: 20px 20px 18px;
            border: 1px solid var(--border);
            border-radius: 14px;
            color: inherit;
            text-decoration: none;
            background: var(--surface);
            backdrop-filter: blur(10px);
            box-shadow: 0 1px 0 rgba(255, 255, 255, 0.65) inset;
            position: relative;
            overflow: hidden;
            transition: transform 0.22s ease, box-shadow 0.22s ease, border-color 0.22s ease;
          }

          .links a::before {
            content: "";
            position: absolute;
            left: 0;
            top: 0;
            bottom: 0;
            width: 4px;
            background: var(--card-accent);
            opacity: 0.92;
          }

          .links a:nth-child(2) { --card-accent: #7c6f64; }
          .links a:nth-child(3) { --card-accent: var(--warn); }
          .links a:nth-child(4) { --card-accent: #4a5d78; }

          .links a:hover {
            transform: translateY(-3px);
            box-shadow:
              0 18px 40px -24px rgba(18, 20, 26, 0.35),
              0 1px 0 rgba(255, 255, 255, 0.65) inset;
            border-color: rgba(18, 20, 26, 0.14);
          }

          .links a:focus-visible {
            outline: 2px solid var(--focus);
            outline-offset: 3px;
          }

          .links strong {
            display: block;
            margin-bottom: 8px;
            font-family: var(--font-ui);
            font-size: 1rem;
            font-weight: 600;
            color: var(--ink);
          }

          .links a p {
            font-size: 0.875rem;
          }

          code {
            font-family: var(--font-mono);
            font-size: 0.84em;
            font-weight: 500;
            padding: 0.12em 0.4em;
            border-radius: 5px;
            background: rgba(15, 107, 92, 0.1);
            color: var(--ink-soft);
          }

          .endpoint-hint {
            margin-top: 28px;
            padding: 16px 18px;
            font-size: 0.9375rem;
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 12px;
            color: var(--ink-soft);
          }

          .endpoint-hint code {
            background: rgba(18, 20, 26, 0.06);
          }

          .site-footer {
            flex-shrink: 0;
            border-top: 1px solid var(--border);
            background: var(--surface);
            backdrop-filter: blur(12px);
            padding-block: 22px;
            font-size: 0.8125rem;
            color: var(--muted);
          }

          .site-footer .inner {
            display: flex;
            flex-wrap: wrap;
            align-items: baseline;
            justify-content: space-between;
            gap: 14px 28px;
          }

          .footer-meta {
            margin: 0;
            font-weight: 500;
            color: var(--ink-soft);
          }

          .footer-links {
            display: flex;
            flex-wrap: wrap;
            gap: 6px 18px;
            list-style: none;
            margin: 0;
            padding: 0;
          }

          .footer-links a {
            color: var(--accent);
            text-decoration: none;
            font-weight: 500;
            border-bottom: 1px solid transparent;
            transition: border-color 0.2s;
          }

          .footer-links a:hover {
            border-bottom-color: var(--accent);
          }

          .footer-links a:focus-visible {
            outline: 2px solid var(--focus);
            outline-offset: 2px;
            border-radius: 2px;
          }

          @media (prefers-color-scheme: dark) {
            :root {
              --ink: #eceae4;
              --ink-soft: #b8b4a8;
              --muted: #8a8578;
              --bg: #121410;
              --bg-deep: #0a0b08;
              --surface: rgba(28, 30, 26, 0.82);
              --surface-solid: #1c1e1a;
              --border: rgba(236, 234, 228, 0.1);
              --accent: #5eead4;
              --accent-glow: rgba(94, 234, 212, 0.12);
              --warn: #fbbf24;
              --focus: #7dd3fc;
            }

            .atmosphere {
              background:
                radial-gradient(1000px 600px at 10% 0%, var(--accent-glow), transparent 50%),
                radial-gradient(800px 480px at 90% 100%, rgba(251, 191, 36, 0.06), transparent 45%),
                linear-gradient(165deg, var(--bg) 0%, var(--bg-deep) 100%);
            }

            .links a {
              box-shadow: 0 1px 0 rgba(255, 255, 255, 0.04) inset;
            }

            .links a:hover {
              box-shadow:
                0 20px 50px -28px rgba(0, 0, 0, 0.75),
                0 1px 0 rgba(255, 255, 255, 0.04) inset;
            }

            code {
              background: rgba(94, 234, 212, 0.12);
              color: var(--ink-soft);
            }

            .endpoint-hint code {
              background: rgba(236, 234, 228, 0.08);
            }

            .header-nav a:hover {
              background: rgba(94, 234, 212, 0.1);
              border-color: rgba(94, 234, 212, 0.2);
            }
          }

          @media (prefers-reduced-motion: reduce) {
            .hero-animate > * {
              animation: none;
            }

            .links a {
              transition: none;
            }

            .links a:hover {
              transform: none;
            }
          }
        </style>
      </head>
      <body>
        <div class="atmosphere" aria-hidden="true"></div>
        <a class="skip-link" href="#main">Skip to main content</a>
        <div class="page">
          <header class="site-header">
            <div class="shell inner">
              <div class="brand">
                Injection Shield
                <span>Research API · ML + LangGraph</span>
              </div>
              <nav class="header-nav" aria-label="Quick links">
                <a href="/docs">Swagger</a>
                <a href="/redoc">ReDoc</a>
                <a href="/health">Health</a>
                <a href="/stats">Stats</a>
                <a href="/incidents">Incidents</a>
              </nav>
            </div>
          </header>

          <main class="site-main" id="main">
            <div class="content hero-animate">
              <p class="eyebrow">Tiered detection pipeline</p>
              <h1>Injection Shield</h1>
              <p class="tagline">HTTP injection detection, without the wait.</p>
              <p class="summary">
                Fast scoring on every request; uncertain traffic passes through instantly while LangGraph
                and an LLM reason about grey-zone cases in the background—incidents and IP reputation
                stay in SQLite for audit and research.
              </p>

              <nav class="links" aria-label="API shortcuts">
                <a href="/docs">
                  <strong>Swagger UI</strong>
                  <p>Explore and run the API interactively.</p>
                </a>
                <a href="/stats">
                  <strong>Detection stats</strong>
                  <p>Incident counts and configured thresholds.</p>
                </a>
                <a href="/incidents">
                  <strong>Recent incidents</strong>
                  <p>Model and LLM decisions in one list.</p>
                </a>
                <a href="/redoc">
                  <strong>ReDoc</strong>
                  <p>OpenAPI reference, reader-friendly layout.</p>
                </a>
              </nav>

              <p class="endpoint-hint">
                <code>POST /analyze</code> — submit a request.
                Grey-zone follow-up: <code>GET /request/{request_id}</code>
              </p>
            </div>
          </main>

          <footer class="site-footer">
            <div class="shell inner">
              <p class="footer-meta">Injection Shield · HTTP injection research</p>
              <ul class="footer-links" aria-label="Footer">
                <li><a href="/docs">OpenAPI</a></li>
                <li><a href="/health">Health</a></li>
                <li><a href="/ip/127.0.0.1">Sample IP JSON</a></li>
              </ul>
            </div>
          </footer>
        </div>
      </body>
    </html>
    """


@app.post("/analyze", response_model=AnalyzeResponse)
async def analyze(req: AnalyzeRequest, background_tasks: BackgroundTasks):
    """Analyze an HTTP request for injection attacks.

    - High confidence attack: blocked immediately (inline, milliseconds)
    - Benign: passed through (inline, milliseconds)
    - Grey zone: passed through now, queued for async LLM analysis
    """
    if db.is_ip_banned(req.source_ip):
        http_request = parse_http_request(
            method=req.method, url=req.url,
            headers=req.headers, body=req.body, source_ip=req.source_ip,
        )
        return AnalyzeResponse(
            request_id=http_request["request_id"],
            confidence=1.0,
            tier="banned",
            decision="attack",
            action_taken="block",
            detail=f"IP {req.source_ip} is currently banned.",
        )

    http_request = parse_http_request(
        method=req.method, url=req.url,
        headers=req.headers, body=req.body, source_ip=req.source_ip,
    )

    confidence = predict(http_request)
    request_id = http_request["request_id"]

    if confidence >= HIGH_THRESHOLD:
        detection_result = {
            "request_id": request_id,
            "confidence": round(confidence, 4),
            "is_attack": True,
            "is_grey_zone": False,
            "tier": "high",
        }
        state = {"http_request": http_request, "detection_result": detection_result}
        result = auto_respond(state)
        resp = result["response"]
        return AnalyzeResponse(
            request_id=request_id,
            confidence=resp["confidence"],
            tier="high",
            decision=resp["decision"],
            action_taken=resp["action_taken"],
            detail=resp["detail"],
        )

    if confidence <= LOW_THRESHOLD:
        detection_result = {
            "request_id": request_id,
            "confidence": round(confidence, 4),
            "is_attack": False,
            "is_grey_zone": False,
            "tier": "low",
        }
        state = {"http_request": http_request, "detection_result": detection_result}
        result = pass_through(state)
        resp = result["response"]
        return AnalyzeResponse(
            request_id=request_id,
            confidence=resp["confidence"],
            tier="low",
            decision=resp["decision"],
            action_taken=resp["action_taken"],
            detail=resp["detail"],
        )

    # Grey zone — pass through immediately, analyze in background
    detection_result = {
        "request_id": request_id,
        "confidence": round(confidence, 4),
        "is_attack": False,
        "is_grey_zone": True,
        "tier": "grey",
    }

    db.update_ip_after_request(
        source_ip=req.source_ip,
        is_attack=False,
        is_grey_zone=True,
    )

    _set_analysis_status(
        request_id,
        "queued",
        queued_at=_now_iso(),
        source_ip=req.source_ip,
    )

    await queue_llm_analysis(http_request, detection_result)

    return AnalyzeResponse(
        request_id=request_id,
        confidence=round(confidence, 4),
        tier="grey",
        decision="pending",
        action_taken="under_review",
        detail=(
            f"Request from {req.source_ip} is in the grey zone "
            f"(confidence {confidence:.2f}). Passed through; "
            f"queued for LLM analysis."
        ),
    )


@app.get("/ip/{source_ip}")
async def get_ip_info(source_ip: str):
    """Get reputation and recent incidents for a source IP."""
    reputation = db.get_ip_reputation(source_ip)
    incidents = db.get_recent_incidents(source_ip, limit=20)
    return {
        "source_ip": source_ip,
        "reputation": reputation,
        "recent_incidents": incidents,
        "is_banned": db.is_ip_banned(source_ip),
    }


@app.get("/incidents")
async def get_incidents(source_ip: str | None = None, limit: int = 50):
    """List recent incidents, optionally filtered by IP."""
    if source_ip:
        return db.get_recent_incidents(source_ip, limit=limit)

    conn = db._get_connection()
    rows = conn.execute(
        """
        SELECT request_id, timestamp, source_ip, confidence,
               decision, decision_source, action_taken
        FROM incidents
        ORDER BY timestamp DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()
    return [dict(row) for row in rows]


@app.get("/stats")
async def get_stats():
    """Get aggregate detection statistics."""
    stats = db.get_incident_stats()
    stats["thresholds"] = {
        "high": HIGH_THRESHOLD,
        "low": LOW_THRESHOLD,
    }
    return stats


@app.get("/request/{request_id}")
async def get_request_status(request_id: str):
    """Get processing status and incident outcome for a specific request_id."""
    incident = db.get_incident_by_request_id(request_id)
    status = _get_analysis_status(request_id)

    if status is None and incident is None:
        return {
            "request_id": request_id,
            "status": "not_found",
            "incident": None,
        }

    if status is None and incident is not None:
        return {
            "request_id": request_id,
            "status": "completed",
            "incident": incident,
        }

    return {
        "request_id": request_id,
        "status": status["status"],
        "analysis": status,
        "incident": incident,
    }
