"""FastAPI server for the HTTP injection detection and response pipeline."""

import asyncio
import datetime
import logging
import threading
from contextlib import asynccontextmanager
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from fastapi import FastAPI, BackgroundTasks, HTTPException
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
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

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
FRONTEND_DIST = _REPO_ROOT / "frontend" / "dist"


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


def _spa_index_response():
    """Serve the built React app shell, or a short message if dist is missing."""
    index = FRONTEND_DIST / "index.html"
    if not index.is_file():
        return HTMLResponse(
            (
                "<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'>"
                "<meta name='viewport' content='width=device-width, initial-scale=1'>"
                "<title>Injection Shield</title></head><body>"
                "<p>Frontend not built. From the repo root run:</p>"
                "<pre>cd frontend && npm ci && npm run build</pre>"
                "</body></html>"
            ),
            status_code=503,
        )
    return FileResponse(index)


def _spa_dist_file_or_none(relative_path: str) -> Path | None:
    """Resolve a file under frontend/dist without path traversal."""
    if not relative_path or relative_path.startswith("assets/"):
        return None
    base = FRONTEND_DIST.resolve()
    candidate = (FRONTEND_DIST / relative_path).resolve()
    try:
        candidate.relative_to(base)
    except ValueError:
        return None
    if candidate.is_file():
        return candidate
    return None


@app.get("/", include_in_schema=False)
async def spa_root():
    """Serve the single-page app entry (same origin as the JSON API)."""
    return _spa_index_response()


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


_spa_assets_dir = FRONTEND_DIST / "assets"
if _spa_assets_dir.is_dir():
    app.mount(
        "/assets",
        StaticFiles(directory=str(_spa_assets_dir)),
        name="spa_assets",
    )


@app.get("/{full_path:path}", include_in_schema=False)
async def spa_history_fallback(full_path: str):
    """Deep links for the React router; JSON API paths are registered above."""
    dist_file = _spa_dist_file_or_none(full_path)
    if dist_file is not None:
        return FileResponse(dist_file)
    index = FRONTEND_DIST / "index.html"
    if not index.is_file():
        raise HTTPException(status_code=503, detail="SPA not built (run: cd frontend && npm run build)")
    return FileResponse(index)
