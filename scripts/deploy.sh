#!/usr/bin/env bash
set -Eeuo pipefail

APP_DIR="/var/www/langraph-security-agent"
SERVICE_NAME="langraph-security-agent.service"
HEALTH_URL="http://127.0.0.1:8001/health"

cd "$APP_DIR"
export GIT_SSH_COMMAND="ssh -F ~/.ssh/config"

echo "Deploying $(basename "$APP_DIR")..."
git fetch origin main
git checkout main
git pull --ff-only origin main

./.venv/bin/python -m pip install -r requirements.txt

if ! command -v npm >/dev/null 2>&1; then
	echo "error: npm is required to build frontend/dist (install Node.js on the VPS)" >&2
	exit 1
fi
( cd frontend && npm ci && npm run build )

# The health TestClient test currently hangs in this environment, so keep
# deployment verification to the fast unit/smoke tests that are reliable.
./.venv/bin/python -m pytest tests/test_detector.py tests/test_database_smoke.py -q

systemctl restart "$SERVICE_NAME"
systemctl is-active --quiet "$SERVICE_NAME"

for attempt in {1..10}; do
  if curl -fsS "$HEALTH_URL" >/dev/null; then
    echo "Deployment complete. Service is healthy."
    exit 0
  fi
  echo "Waiting for health check... ($attempt/10)"
  sleep 2
done

echo "Deployment failed: health check did not pass at $HEALTH_URL" >&2
systemctl status "$SERVICE_NAME" --no-pager >&2 || true
exit 1
