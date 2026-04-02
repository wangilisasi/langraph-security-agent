# TODO

## Core implementation

- [ ] Replace the placeholder model-loading code in `app/detection/detector.py::load_model()` with the real trained classifier loader.
- [ ] Replace the placeholder inference logic in `app/detection/detector.py::predict()` with the real feature extraction + prediction pipeline.

## Research / evaluation

- [ ] Add batch evaluation + metrics collection for labeled HTTP request datasets.
- [ ] Export incident and evaluation data to CSV/pandas-friendly format for thesis analysis.

## Future features

- [ ] Add optional web/RAG-assisted lookup for grey-zone or high-risk cases.
- [ ] Use external security references such as OWASP guidance, attack-signature references, or curated threat intel when the local classifier/agent is uncertain.
- [ ] Keep external lookup optional so the core pipeline still works fully offline without Tavily or other search dependencies.
