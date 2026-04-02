# LangGraph Security Agent

A LangGraph-based HTTP injection attack detection and response agent for PhD research.

## What it does

- Runs a tiered detection pipeline for HTTP requests
- Uses a fast ML detector inline for clear-cut cases
- Sends grey-zone requests to an LLM agent asynchronously
- Logs incidents and IP reputation in SQLite
- Exposes a FastAPI server for analysis, stats, and incident lookup

## Project layout

- `server.py` — compatibility FastAPI entrypoint (`app` import for `uvicorn server:app`)
- `app/api/server.py` — FastAPI routes and async grey-zone queueing
- `app/graph/security_agent.py` — LangGraph security workflow
- `app/detection/detector.py` — ML wrapper and confidence routing
- `app/graph/response_nodes.py` — fast-path auto-response logic
- `app/tools/security_tools.py` — tools used by the LLM for grey-zone analysis
- `app/storage/database.py` — SQLite storage for incidents and IP reputation
- `tests/` — minimal pytest scaffold
- `ARCHITECTURE.md` — design notes
- `PROGRESS.md` — implementation status

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
python -m uvicorn app.api.server:app --port 8000
```

Compatibility entrypoint (still works):

```bash
python -m uvicorn server:app --port 8000
```

Docs:
- Swagger UI: `http://127.0.0.1:8000/docs`

## Notes

- `app/detection/detector.py` still contains a placeholder model interface.
- Replace `load_model()` and `predict()` with your real classifier.
- SQLite data is stored under `output/`.

## TODO

- See `TODO.md` for implementation backlog and future feature ideas.
