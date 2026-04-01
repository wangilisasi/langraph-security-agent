# LangGraph Security Agent

A LangGraph-based HTTP injection attack detection and response agent for PhD research.

## What it does

- Runs a tiered detection pipeline for HTTP requests
- Uses a fast ML detector inline for clear-cut cases
- Sends grey-zone requests to an LLM agent asynchronously
- Logs incidents and IP reputation in SQLite
- Exposes a FastAPI server for analysis, stats, and incident lookup

## Main files

- `server.py` — FastAPI entrypoint
- `security_agent.py` — LangGraph security workflow
- `detector.py` — ML wrapper and confidence routing
- `response_nodes.py` — fast-path auto-response logic
- `security_tools.py` — tools used by the LLM for grey-zone analysis
- `database.py` — SQLite storage for incidents and IP reputation
- `ARCHITECTURE.md` — design notes
- `PROGRESS.md` — implementation status

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
python -m uvicorn server:app --port 8000
```

Docs:
- Swagger UI: `http://127.0.0.1:8000/docs`

## Notes

- `detector.py` still contains a placeholder model interface.
- Replace `load_model()` and `predict()` with your real classifier.
- SQLite data is stored under `output/`.
