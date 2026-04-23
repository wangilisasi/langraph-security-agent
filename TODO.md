# TODO

## Core implementation

1. Replace the placeholder model-loading code in app/detection/detector.py::load_model() with the real trained classifier loader.
2. Replace the placeholder inference logic in app/detection/detector.py::predict() with the real feature extraction + prediction pipeline.

## Research / evaluation

1. Refresh memory on sequence diagrams, then draw sequence diagrams for both the default FastAPI-led architecture and the full-LangGraph variant.
2. Add batch evaluation plus metrics collection for labeled HTTP request datasets.
3. Export incident and evaluation data to CSV/pandas-friendly format for thesis analysis.
4. Update the draft paper to reflect that the hybrid evaluation harness now exists under `evals/` and remove stale text claiming evaluation tooling is missing.

## Architecture experiments

1. Compare the default FastAPI-led architecture with the full-LangGraph variant on the same labeled dataset.
2. Measure whether full-graph orchestration adds meaningful latency or improves maintainability/explainability, while preserving async grey-zone semantics.
3. Keep experiment outputs isolated by architecture variant to avoid mixing incident/evaluation data.
4. Restore or implement the documented full-LangGraph variant so the paper's architecture-comparison claim matches the codebase.

## Detector integration

1. Replace the placeholder detector in `app/detection/detector.py` with the real trained HTTP injection classifier.
2. Implement the actual feature extraction and probability prediction path in `predict()`.
3. Recalibrate `HIGH_THRESHOLD` and `LOW_THRESHOLD` against the final model rather than the placeholder lexical scorer.

## Testing / validation

1. Add API tests for `/analyze`, `/request/{request_id}`, `/stats`, `/incidents`, and `/ip/{source_ip}`.
2. Add integration tests for grey-zone processing, including queued → running → completed status transitions.
3. Add tests for repeat-offender escalation and temporary IP ban behavior.
4. Add tool-level tests for `log_security_incident`, `block_ip`, and `send_alert`.

## Alerting / integrations

1. Replace file-only alert logging with a real alerting integration such as webhook, Slack, email, or SIEM forwarding.
2. Keep the current file logger as a fallback sink for local development and offline demos.

## Performance / caching (planned)

1. Add Redis integration for hot-path ban checks with REDIS_URL plus optional REDIS_ENABLED config.
2. Implement cache-first IP ban lookup in the analyze path with SQLite fallback when cache misses or Redis is unavailable.
3. Cache temporary bans with TTL based on ban_until, and cache permanent bans without TTL.
4. Add optional short-lived negative cache for known non-banned IPs to reduce repeated DB reads.
5. Keep SQLite as source of truth and update or invalidate Redis keys whenever ban state changes.
6. Add tests for cache hit, cache miss fallback, temp ban expiry behavior, and Redis-down fallback.

## Future features

1. Add optional web/RAG-assisted lookup for grey-zone or high-risk cases.
2. Use external security references such as OWASP guidance, attack-signature references, or curated threat intel when the local classifier/agent is uncertain.
3. Keep external lookup optional so the core pipeline still works fully offline without Tavily or other search dependencies.
