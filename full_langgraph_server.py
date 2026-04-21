"""FastAPI server variant where LangGraph owns the full request pipeline."""

import asyncio
import logging
from contextlib import asynccontextmanager
from concurrent.futures import ThreadPoolExecutor

from fastapi import FastAPI
from pydantic import BaseModel, Field

from detector import parse_http_request, load_model
from full_security_agent import full_security_agent, run_grey_zone_analysis
import database as db

logger = logging.getLogger("full_security_server")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

_executor = ThreadPoolExecutor(max_workers=4)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup / shutdown hooks."""
    load_model()
    db.init_db()
    logger.info("Full-graph security server started")
    yield
    _executor.shutdown(wait=False)
    logger.info("Full-graph security server stopped")


app = FastAPI(
    title="HTTP Injection Detection API (Full LangGraph Variant)",
    description="All request orchestration happens inside LangGraph.",
    version="0.2.0",
    lifespan=lifespan,
)


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


def _run_llm_analysis(http_request: dict, detection_result: dict) -> None:
    request_id = detection_result["request_id"]
    try:
        logger.info("Full-graph LLM analysis started for %s", request_id)
        run_grey_zone_analysis(http_request, detection_result)
        logger.info("Full-graph LLM analysis completed for %s", request_id)
    except Exception:
        logger.exception("Full-graph LLM analysis failed for %s", request_id)


async def queue_llm_analysis(http_request: dict, detection_result: dict) -> None:
    loop = asyncio.get_event_loop()
    loop.run_in_executor(_executor, _run_llm_analysis, http_request, detection_result)


@app.post("/analyze", response_model=AnalyzeResponse)
async def analyze(req: AnalyzeRequest):
    http_request = parse_http_request(
        method=req.method,
        url=req.url,
        headers=req.headers,
        body=req.body,
        source_ip=req.source_ip,
    )

    result = full_security_agent.invoke({"http_request": http_request})
    response = result["response"]
    detection = result["detection_result"]

    if detection["tier"] == "grey":
        await queue_llm_analysis(http_request, detection)

    return AnalyzeResponse(
        request_id=detection["request_id"],
        confidence=detection["confidence"],
        tier=detection["tier"],
        decision=response["decision"],
        action_taken=response["action_taken"],
        detail=response["detail"],
    )


@app.get("/ip/{source_ip}")
async def get_ip_info(source_ip: str):
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
    return db.get_incident_stats()
