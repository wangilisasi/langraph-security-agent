# Frontend architecture (Injection Shield SPA)

This document summarizes how the Vite + React UI is structured, how it talks to FastAPI, and the main changes introduced after the original inline-HTML root page.

## Overview

- **Stack:** React 19, TypeScript, Vite 8, React Router 7, Tailwind CSS v4 (`@tailwindcss/vite`), TanStack Query (React Query).
- **Deployment:** The built app lives in `frontend/dist/`. FastAPI serves `index.html`, `/assets/*`, and a SPA fallback for client-side routes on the **same origin** as the JSON API (no CORS for browser calls to `/stats`, `/incidents`, etc.).
- **Local dev:** Run uvicorn on one port and `npm run dev` in `frontend/`; Vite proxies API and OpenAPI paths (see `vite.config.ts`, env `VITE_DEV_API`).

## Directory layout

```
frontend/
  src/
    api/                 # HTTP + query hooks
      http.ts            # fetchJson, ApiError
      query-keys.ts      # stable TanStack Query keys
      dashboard-queries.ts  # useStatsQuery, useIncidentsQuery
    lib/
      query-client.ts    # QueryClient factory + defaults
      query-error.ts     # getQueryErrorMessage helper
    pages/               # Route screens (Monitoring, Audit, Home)
    Layout.tsx           # Shell + nav
    App.tsx              # Routes
    main.tsx             # QueryClientProvider + BrowserRouter
    index.css            # Tailwind import, @theme inline tokens, legacy component CSS
```

## Routing

| Path           | Purpose                                      |
|----------------|----------------------------------------------|
| `/`            | Home / marketing-style landing               |
| `/monitoring`  | Stats UI (`GET /stats`)                      |
| `/audit`       | Incidents table (`GET /incidents?limit=50`) |

Deep links rely on FastAPI returning `index.html` for unknown GET paths **after** real API routes are registered (see `app/api/server.py`).

## Data fetching

Earlier versions used `useEffect` + manual `fetch` and tripped the `react-hooks/set-state-in-effect` lint rule.

**Current approach:** [TanStack Query](https://tanstack.com/query/latest) with:

- Shared **`QueryClient`** defaults: `staleTime` 60s, `gcTime` 5m, `retry: 1`, `refetchOnWindowFocus: true`.
- **`useStatsQuery()`** / **`useIncidentsQuery(limit)`** in `src/api/dashboard-queries.ts`.
- **`fetchJson`** in `src/api/http.ts` for same-origin JSON, throwing **`ApiError`** on non-OK responses.

## Styling

- **Tailwind v4** is loaded via `@import 'tailwindcss'` in `index.css`.
- Design tokens are defined on `:root` (including dark mode overrides). **`--stack-display` / `--stack-sans` / `--stack-mono`** alias font stacks so `@theme inline` can expose utilities without circular `var()` references.
- **Semantic utilities** include `text-ink`, `bg-bg`, `border-border`, `font-sans`, `font-display`, `font-mono`, etc., while existing class-based rules (cards, table, atmosphere) remain for layout-heavy pieces.

## Production build & deploy

- From repo root: `cd frontend && npm ci && npm run build` produces `frontend/dist/`.
- The server **`scripts/deploy.sh`** runs that build on the VPS before smoke tests and `systemctl restart`, so `dist/` always matches the checked-out revision.

## Environment (LLM / app config)

The React app does **not** read OpenRouter secrets. Grey-zone LLM configuration stays in the FastAPI process (`.env` on the server, loaded from repo root in `app/graph/security_agent.py`).

## Related files

- API + SPA mount: `app/api/server.py`
- Deploy workflow: `.github/workflows/deploy.yml` → `scripts/deploy.sh`
- Example env (no secrets): `.env.example`
