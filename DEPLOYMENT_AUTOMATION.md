# Deployment Automation Notes

This repo was prepared for automatic deployment from GitHub `main` to the
server at `/var/www/langraph-security-agent`.

## Goal

When code is pushed to GitHub `main`, the live FastAPI service on this server
should update automatically:

1. GitHub receives a push on `main`.
2. GitHub Actions starts a workflow.
3. The workflow connects to this server over SSH.
4. The server pulls the latest `main`.
5. Dependencies are updated.
6. Smoke tests run.
7. `langraph-security-agent.service` restarts.
8. `/health` is checked.

## Existing Server Service

The app already runs under systemd:

```text
langraph-security-agent.service
```

The service is defined at:

```text
/etc/systemd/system/langraph-security-agent.service
```

Important service details:

```text
User=emil
Group=emil
WorkingDirectory=/var/www/langraph-security-agent
EnvironmentFile=/var/www/langraph-security-agent/.env
ExecStart=/var/www/langraph-security-agent/.venv/bin/uvicorn app.api.server:app --host 127.0.0.1 --port 8001
```

The app listens on **127.0.0.1:8001** only; TLS and a public hostname should be handled by a reverse proxy (for example Nginx) with `proxy_pass http://127.0.0.1:8001`. The same process serves the API, Swagger (`/docs`), and the React SPA from `frontend/dist`, so each deploy must run **`npm ci && npm run build`** in `frontend/` (see `scripts/deploy.sh`).

The health endpoint is:

```text
http://127.0.0.1:8001/health
```

## Files Added

### `.github/workflows/deploy.yml`

This workflow runs on pushes to `main`:

```yaml
on:
  push:
    branches:
      - main
```

It uses a GitHub-hosted runner:

```yaml
runs-on: ubuntu-latest
```

It SSHes into the server using GitHub repository secrets:

```text
DEPLOY_HOST
DEPLOY_USER
DEPLOY_PORT
DEPLOY_SSH_KEY
```

Then it runs the server deployment script.

### `scripts/deploy.sh`

This script performs the deployment on the server:

1. Changes into `/var/www/langraph-security-agent`.
2. Forces Git to use the local SSH config:

   ```bash
   export GIT_SSH_COMMAND="ssh -F ~/.ssh/config"
   ```

3. Fetches and fast-forwards `main`:

   ```bash
   git fetch origin main
   git checkout main
   git pull --ff-only origin main
   ```

4. Installs dependencies:

   ```bash
   ./.venv/bin/python -m pip install -r requirements.txt
   ```

5. Builds the React UI into `frontend/dist` (requires `npm` / Node on the server):

   ```bash
   cd frontend && npm ci && npm run build && cd ..
   ```

6. Runs the reliable smoke tests:

   ```bash
   ./.venv/bin/python -m pytest tests/test_detector.py tests/test_database_smoke.py -q
   ```

7. Restarts the service:

   ```bash
   systemctl restart langraph-security-agent.service
   ```

8. Checks the health endpoint:

   ```bash
   curl -fsS http://127.0.0.1:8001/health
   ```

The full `tests/test_api_health.py` test is intentionally not used during
deployment because `TestClient` was hanging in this server environment.

## SSH Details

The server's SSH port is:

```text
64295
```

SSH is listening on:

```text
0.0.0.0:64295
[::]:64295
```

A dedicated deploy key was created:

```text
/home/emil/.ssh/langraph_security_agent_actions
/home/emil/.ssh/langraph_security_agent_actions.pub
```

The public key was added to:

```text
/home/emil/.ssh/authorized_keys
```

The private key must be stored in GitHub as:

```text
DEPLOY_SSH_KEY
```

## Required GitHub Secrets

Add these under:

```text
Repository -> Settings -> Secrets and variables -> Actions -> Secrets
```

Use **Secrets**, not Variables.

```text
DEPLOY_HOST=82.208.21.78
DEPLOY_USER=emil
DEPLOY_PORT=64295
DEPLOY_SSH_KEY=<contents of /home/emil/.ssh/langraph_security_agent_actions>
```

To print the private key for `DEPLOY_SSH_KEY`:

```bash
cat /home/emil/.ssh/langraph_security_agent_actions
```

## Service Restart Permission

Initially, `emil` could not restart the systemd service non-interactively:

```text
Interactive authentication required.
```

A narrow polkit rule was prepared and installed so user `emil` can manage only:

```text
langraph-security-agent.service
```

The rule file is:

```text
/etc/polkit-1/rules.d/49-langraph-security-agent.rules
```

It allows `emil` to start, stop, restart, reload, or reload-or-restart only this
one unit.

This was verified successfully:

```bash
systemctl restart langraph-security-agent.service
```

## GitHub Actions Billing Blocker

The workflow was pushed and did trigger on GitHub, but it did not execute.

GitHub showed:

```text
GitHub Actions workflows can't be executed on this repository.
Your account's billing is currently locked. Please update your payment information.
```

Because of that, the automation could not reach this server.

The server was still behind GitHub after commit `a6cd94d`:

```text
local HEAD:   63560e8 Add GitHub Actions deployment
origin/main:  a6cd94d Remove three-step pipeline strip from landing page
```

This means the push reached GitHub, but GitHub Actions did not run the deploy.

## Current Status

Completed:

- Deployment workflow added.
- Server deploy script added.
- Dedicated GitHub Actions SSH key created.
- Public key authorized for user `emil`.
- SSH port confirmed as `64295`.
- Service restart permission configured through polkit.
- Health endpoint confirmed working.
- Deployment automation commit pushed to GitHub.

Blocked:

- GitHub Actions cannot run until the GitHub account billing issue is fixed.

## When Billing Is Fixed

1. Confirm the GitHub secrets are set under Actions secrets.
2. Go to:

   ```text
   GitHub repo -> Actions -> Deploy
   ```

3. Rerun the failed workflow, or push a new commit to `main`.
4. Watch the `Deploy over SSH` step.
5. After it finishes, verify on the server:

   ```bash
   cd /var/www/langraph-security-agent
   git status --short --branch
   git log --oneline -3
   systemctl status langraph-security-agent.service --no-pager
   curl -fsS http://127.0.0.1:8001/health
   ```

Expected result:

```text
local main is up to date with origin/main
langraph-security-agent.service is active
/health returns {"status":"ok","version":"0.1.0"}
```

## Manual Deployment Fallback

Until GitHub Actions works, deploy manually:

```bash
cd /var/www/langraph-security-agent
scripts/deploy.sh
```

This uses the same deployment logic the GitHub workflow will use later.

## Alternative Free Automation

If GitHub Actions remains unavailable, use a GitHub webhook instead:

1. Expose a small webhook endpoint on this server.
2. Configure a GitHub push webhook.
3. Verify the webhook secret.
4. Run `scripts/deploy.sh` on valid `main` push events.

This avoids GitHub Actions runners and billing, but it requires careful webhook
security.
