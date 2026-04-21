# TODO

## Core implementation

- [ ] Replace the placeholder model-loading code in `detector.py::load_model()` with the real trained classifier loader.
- [ ] Replace the placeholder inference logic in `detector.py::predict()` with the real feature extraction + prediction pipeline.

## Research / evaluation

- [ ] Add batch evaluation + metrics collection for labeled HTTP request datasets.
- [ ] Add an evaluator component so the agent can systematically assess detections, responses, and overall decision quality.
- [ ] Export incident and evaluation data to CSV/pandas-friendly format for thesis analysis.

## Architecture experiments

- [ ] Refresh memory on sequence diagrams, then draw sequence diagrams for both the default FastAPI-led architecture and the full-LangGraph variant.
- [ ] Compare the default FastAPI-led architecture with the full-LangGraph variant on the same labeled dataset.
- [ ] Measure whether full-graph orchestration adds meaningful latency or improves maintainability/explainability, while preserving async grey-zone semantics.
- [x] Keep experiment outputs isolated by architecture variant to avoid mixing incident/evaluation data.

## Future features

- [ ] Add local security-knowledge RAG for grey-zone analysis, starting with OWASP and curated injection references.
- [ ] Add similar-incident retrieval over prior logged incidents to support consistency and explainability.
- [ ] Add optional web/RAG-assisted lookup for grey-zone or high-risk cases.
- [ ] Use external security references such as OWASP guidance, attack-signature references, or curated threat intel when the local classifier/agent is uncertain.
- [ ] Keep external lookup optional so the core pipeline still works fully offline without Tavily or other search dependencies.
