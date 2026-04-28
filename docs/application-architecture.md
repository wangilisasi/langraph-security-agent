# Application architecture (Injection Shield)

High-level view of how the browser, FastAPI, the React UI, and background work fit together.

## ASCII diagram

```
┌──────────────────────────────────────────────────────────────────────────┐
│                              Browser                                      │
│  ┌─────────────────────┐    ┌─────────────────────────────────────────┐  │
│  │ React SPA (Vite dev │    │ Same build served from FastAPI in prod   │  │
│  │  or dist/ assets)   │    │  /  /monitoring  /audit  + /assets/*     │  │
│  └──────────┬──────────┘    └────────────────────┬────────────────────┘  │
│             │  fetch '/', '/stats', '/incidents'  │  open /docs, /redoc   │
└─────────────┼────────────────────────────────────┼────────────────────────┘
              │ same-origin (prod)                 │
              │     or Vite proxy → API (dev)        │
              ▼                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  FastAPI  (uvicorn :8000 local / :8001 VPS, behind Nginx in prod)           │
│  ┌─────────────────────────────────────────────────────────────────────────┐│
│  │ • GET  /  + SPA fallback → index.html (React router handles paths)     ││
│  │ • GET  /assets/*      → Vite-built JS/CSS                                ││
│  │ • GET  /health, /stats, /incidents, /ip/…, /request/…  → JSON          ││
│  │ • POST /analyze       → detector + maybe queue grey-zone work          ││
│  │ • GET  /docs, /redoc, /openapi.json  → OpenAPI UIs                      ││
│  └─────────────────────────────────────────────────────────────────────────┘│
│                                                                              │
│  ┌──────────────────┐     ┌─────────────────────────────────────────────┐ │
│  │ Tiered detector  │     │ Grey zone (async / thread pool)               │ │
│  │ (ML predict)     │────▶│ LangGraph agent → OpenRouter (Chat API)       │ │
│  └──────────────────┘     │ tools + incidents / IP rep in SQLite         │ │
│                             └─────────────────────────────────────────────┘ │
└──────────────────────────────────────────────┬──────────────────────────────┘
                                               │
                                               ▼
                                    ┌──────────────────┐
                                    │ SQLite (output/) │
                                    │ incidents, IP…   │
                                    └──────────────────┘

  Dev-only shortcut:
  ┌─────────────┐     proxy /stats, /analyze, …     ┌─────────────┐
  │ Vite :5173  │ ──────────────────────────────────▶ │ FastAPI     │
  │ (npm run dev)│                                    │             │
  └─────────────┘                                    └─────────────┘
```

**Read in one line:** in production the browser talks to **one backend**: FastAPI both **serves the React app** and **implements the JSON API**; grey-zone analysis uses **LangGraph + OpenRouter** and persists to **SQLite**. In development, **Vite** adds a **proxy** so the SPA still calls the same paths as in production.

---

## Build vs serve (React + FastAPI)

### FastAPI does **not** build React

The UI is **compiled ahead of time** by **Vite** when you run:

```bash
cd frontend && npm run build
```

That writes **`frontend/dist/`** (`index.html`, hashed JS/CSS under `assets/`). Your **deploy pipeline** (e.g. `scripts/deploy.sh`) runs this on the server before restarting the API. FastAPI does **not** run `npm` or compile TypeScript on each browser request.

### FastAPI **does** serve the built app

At **runtime**, FastAPI only **reads files already in `dist/`** and returns them to the browser:

- **`GET /`** → `frontend/dist/index.html`
- **`GET /assets/...`** → static files under `frontend/dist/assets/`
- **Other client-only paths** (e.g. `/monitoring`) → same `index.html` so **React Router** can run in the browser

The **JSON API** (`/stats`, `/analyze`, …) is implemented by normal FastAPI routes in the **same process**.

**Summary**

| Step | Tool | What happens |
|------|------|----------------|
| **Build** | Node + Vite (`npm run build`) | Produces `frontend/dist/` |
| **Serve** | FastAPI + Starlette | Sends those files + handles API routes |

More detail on the SPA codebase: [frontend-architecture.md](./frontend-architecture.md).
