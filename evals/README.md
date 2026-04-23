# Evaluation Harness

This directory contains the minimal batch evaluation entrypoint for the paper's
evaluation section.

## Layout

- `evaluate.py` - batch runner for labeled HTTP request datasets
- `data/` - place CSV or JSONL evaluation datasets here

Generated artifacts are written outside this folder by default:

- `output/eval/<run>/results.csv`
- `output/eval/<run>/summary.json`
- `output/eval/<run>/incidents.csv`
- `output/eval/<run>/ip_reputation.csv`

## Supported dataset columns

The evaluation runner expects these fields:

- `sample_id`
- `method`
- `url`
- `headers` as a JSON object string, for example `{"User-Agent":"curl"}`
- `body`
- `source_ip`
- `label` with value `attack` or `benign`
- `attack_type`

## Example CSV

```csv
sample_id,method,url,headers,body,source_ip,label,attack_type
1,GET,/health,{},,10.0.0.1,benign,none
2,POST,/login,{},"username=admin' OR 1=1 --",10.0.0.2,attack,sqli
```

## Usage

Hybrid pipeline evaluation:

```bash
OPENROUTER_API_KEY=... \
python evals/evaluate.py \
  --dataset evals/data/http_eval.csv \
  --output-dir output/eval/hybrid_run
```

## Notes

- The evaluation script reuses the existing detector, response nodes, LangGraph
  agent, and SQLite storage layer.
- The evaluator measures the full hybrid pipeline described in the paper.
- `OPENROUTER_API_KEY` is required because grey-zone samples are sent through the
  LLM agent synchronously for measurement.
