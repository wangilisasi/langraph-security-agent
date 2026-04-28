"""Test harness defaults (import order: pytest loads this before test modules)."""

import os

# `app.api.server` imports the LangGraph agent, which builds ChatOpenAI at import time.
os.environ.setdefault(
    "OPENROUTER_API_KEY",
    "test-dummy-openrouter-key-for-local-pytest",
)
