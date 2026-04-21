# LangGraph Security Agent

A LangGraph-based HTTP injection attack detection and response agent for PhD research.

## What it does

- Runs a tiered detection pipeline for HTTP requests
- Uses a fast ML detector inline for clear-cut cases
- Lets the FastAPI layer own live threshold routing and immediate responses
- Sends grey-zone requests to a LangGraph LLM analysis workflow asynchronously
- Logs incidents and IP reputation in SQLite
- Exposes a FastAPI server for analysis, stats, and incident lookup

## Main files

- `server.py` — FastAPI entrypoint and live request orchestrator
- `security_agent.py` — LangGraph grey-zone analysis workflow
- `detector.py` — ML wrapper and confidence thresholds
- `response_nodes.py` — fast-path auto-response logic for high/low confidence cases
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
- Default variant Swagger UI: `http://127.0.0.1:8000/docs`
- Full-LangGraph variant Swagger UI: `http://127.0.0.1:8001/docs`

## Notes

- `detector.py` still contains a placeholder model interface.
- Replace `load_model()` and `predict()` with your real classifier.
- FastAPI is the single source of truth for live threshold routing.
- LangGraph is only used for asynchronous grey-zone analysis.
- SQLite data is stored under `output/`.

## Variants

### Default variant
- `server.py`
- FastAPI owns live threshold routing
- LangGraph is used only for async grey-zone analysis
- Default DB path: `output/security.db`

### Full LangGraph variant
- `full_langgraph_server.py`
- FastAPI is a thin transport wrapper
- LangGraph owns ban checks, detection, routing, and immediate fast-path decisions
- Grey-zone requests still return immediately and are analyzed asynchronously in the background
- Uses its own DB by default:
  - `output/full_graph/security_full_graph.db`

Example:

```bash
python -m uvicorn full_langgraph_server:app --port 8001
```

Override example:

```bash
SECURITY_OUTPUT_DIR=output/another_experiment \
SECURITY_DB_FILENAME=security_variant.db \
python -m uvicorn full_langgraph_server:app --port 8001
```

## TODO

- See `TODO.md` for implementation backlog and future feature ideas.
