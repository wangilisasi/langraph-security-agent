# Testing Guide

This guide shows how to test the HTTP injection detection service locally.

## 1. Prerequisites

1. Python virtual environment exists at `.venv/`.
2. Dependencies are installed:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

3. Environment variables are configured (copy `.env.example` to `.env` if needed).

## 2. Start the API

Run the server from the project root:

```powershell
.\.venv\Scripts\python.exe -m uvicorn app.api.server:app --host 127.0.0.1 --port 8000
```

You should see:

- `Application startup complete`
- `Uvicorn running on http://127.0.0.1:8000`

## 3. Manual testing in Swagger

1. Open `http://127.0.0.1:8000/docs`.
2. Use `POST /analyze` to submit test payloads.
3. Use these read endpoints to inspect results:
- `GET /stats`
- `GET /incidents`
- `GET /ip/{source_ip}`
- `GET /request/{request_id}`

## 4. PowerShell test commands

Open a second terminal while the server is running.

### 4.1 Benign request (low tier)

```powershell
$req = @{ method="GET"; url="/api/products"; source_ip="10.0.0.1" } | ConvertTo-Json
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/analyze -ContentType "application/json" -Body $req
```

Expected:

- `tier`: `low`
- `decision`: `benign`
- `action_taken`: `log_only`

### 4.2 Grey-zone request (async LLM path)

```powershell
$req = @{ method="POST"; url="/api/search"; body="q=select * from users where name=''x'' or 1=1"; source_ip="10.0.0.99" } | ConvertTo-Json
$resp = Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/analyze -ContentType "application/json" -Body $req
$resp | ConvertTo-Json -Depth 5
```

Expected immediate response:

- `tier`: `grey`
- `decision`: `pending`
- `action_taken`: `under_review`

Then check follow-up state:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/ip/10.0.0.99
Invoke-RestMethod "http://127.0.0.1:8000/incidents?limit=20"
$requestId = $resp.request_id
Invoke-RestMethod ("http://127.0.0.1:8000/request/" + $requestId) | ConvertTo-Json -Depth 6
```

Request status endpoint values:

- `queued`: request accepted and waiting for background processing
- `running`: background LLM analysis in progress
- `completed`: analysis finished
- `failed`: background analysis raised an exception
- `not_found`: unknown request ID

You can poll status until it finishes:

```powershell
do {
  $statusResp = Invoke-RestMethod ("http://127.0.0.1:8000/request/" + $requestId)
  $statusResp | ConvertTo-Json -Depth 6
  Start-Sleep -Seconds 2
} while ($statusResp.status -in @("queued", "running"))
```

### 4.3 High-confidence attack and repeat-offender ban

The placeholder model scores based on pattern hits. This payload includes many suspicious patterns and should reach high confidence.

```powershell
1..3 | ForEach-Object {
  $req = @{ method="POST"; url="/api/login"; body="select union <script> '' or 1=1 drop table exec( ${"; source_ip="10.0.0.77" } | ConvertTo-Json
  Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/analyze -ContentType "application/json" -Body $req
}
```

Then send a normal request from the same IP:

```powershell
$req = @{ method="GET"; url="/health"; source_ip="10.0.0.77" } | ConvertTo-Json
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/analyze -ContentType "application/json" -Body $req
```

Expected:

- Follow-up request should be blocked due to temporary ban.

Verify:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/ip/10.0.0.77
Invoke-RestMethod http://127.0.0.1:8000/stats
```

## 5. Automated tests

Run unit/smoke tests:

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

## 6. Troubleshooting

1. Port already in use:
- Stop the existing process on `8000` or run uvicorn on another port.

Example alternate port:

```powershell
.\.venv\Scripts\python.exe -m uvicorn app.api.server:app --host 127.0.0.1 --port 8001
```

2. Missing packages:
- Re-run `pip install -r requirements.txt` in `.venv`.

3. Grey-zone LLM path not producing an incident quickly:
- It runs asynchronously in a background thread.
- Check server logs for LLM/tool call activity.

4. No OpenRouter key:
- Grey-zone path may fail to complete LLM reasoning without `OPENROUTER_API_KEY`.
- Low/high inline model paths still work.
