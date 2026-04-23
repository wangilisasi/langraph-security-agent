#!/usr/bin/env python3
"""Minimal batch evaluation harness for the HTTP injection pipeline.

This script keeps evaluation self-contained under ``evals/`` while reusing the
existing detector, response nodes, LangGraph agent, and SQLite storage layer.

Outputs written to the selected output directory:
    - results.csv
    - summary.json
    - incidents.csv
    - ip_reputation.csv
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import os
import statistics
import sys
import time
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run batch evaluation for the HTTP injection detection pipeline."
    )
    parser.add_argument(
        "--dataset",
        required=True,
        help="Path to a CSV or JSONL dataset with labeled HTTP requests.",
    )
    parser.add_argument(
        "--output-dir",
        default="output/eval/run1",
        help="Directory for evaluation outputs and the isolated SQLite database.",
    )
    parser.add_argument(
        "--high-threshold",
        type=float,
        default=0.95,
        help="High-confidence threshold for immediate block.",
    )
    parser.add_argument(
        "--low-threshold",
        type=float,
        default=0.15,
        help="Low-confidence threshold for immediate benign pass-through.",
    )
    parser.add_argument(
        "--db-filename",
        default="security_eval.db",
        help="SQLite filename to create inside the output directory.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Optional max number of samples to evaluate.",
    )
    return parser.parse_args()


def ensure_output_env(output_dir: Path, db_filename: str) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    os.environ["SECURITY_OUTPUT_DIR"] = str(output_dir)
    os.environ["SECURITY_DB_FILENAME"] = db_filename


def normalize_label(raw_label: str) -> str:
    label = (raw_label or "").strip().lower()
    if label not in {"attack", "benign"}:
        raise ValueError(f"Unsupported label '{raw_label}'. Expected 'attack' or 'benign'.")
    return label


def parse_headers(raw_headers: Any) -> dict[str, str]:
    if raw_headers in (None, "", {}):
        return {}
    if isinstance(raw_headers, dict):
        return {str(k): str(v) for k, v in raw_headers.items()}

    try:
        parsed = json.loads(raw_headers)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid headers JSON: {raw_headers}") from exc

    if not isinstance(parsed, dict):
        raise ValueError("headers must decode to a JSON object")

    return {str(k): str(v) for k, v in parsed.items()}


def load_dataset(dataset_path: Path, limit: int | None = None) -> list[dict[str, Any]]:
    if not dataset_path.exists():
        raise FileNotFoundError(f"Dataset not found: {dataset_path}")

    rows: list[dict[str, Any]] = []

    if dataset_path.suffix.lower() == ".csv":
        with dataset_path.open("r", encoding="utf-8", newline="") as fh:
            reader = csv.DictReader(fh)
            for index, row in enumerate(reader, start=1):
                rows.append(normalize_dataset_row(row, index))
                if limit is not None and len(rows) >= limit:
                    break
        return rows

    if dataset_path.suffix.lower() == ".jsonl":
        with dataset_path.open("r", encoding="utf-8") as fh:
            for index, line in enumerate(fh, start=1):
                line = line.strip()
                if not line:
                    continue
                rows.append(normalize_dataset_row(json.loads(line), index))
                if limit is not None and len(rows) >= limit:
                    break
        return rows

    raise ValueError("Dataset must be .csv or .jsonl")


def normalize_dataset_row(row: dict[str, Any], index: int) -> dict[str, Any]:
    sample_id = str(row.get("sample_id") or index)
    return {
        "sample_id": sample_id,
        "method": str(row.get("method") or "GET"),
        "url": str(row.get("url") or "/"),
        "headers": parse_headers(row.get("headers")),
        "body": str(row.get("body") or ""),
        "source_ip": str(row.get("source_ip") or f"10.0.0.{(index % 250) + 1}"),
        "label": normalize_label(str(row.get("label") or "")),
        "attack_type": str(row.get("attack_type") or "unknown"),
    }


def percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    if len(values) == 1:
        return values[0]
    ordered = sorted(values)
    rank = (len(ordered) - 1) * pct
    lower = math.floor(rank)
    upper = math.ceil(rank)
    if lower == upper:
        return ordered[lower]
    weight = rank - lower
    return ordered[lower] * (1 - weight) + ordered[upper] * weight


def safe_div(numerator: float, denominator: float) -> float:
    if denominator == 0:
        return 0.0
    return numerator / denominator


def compute_binary_metrics(rows: list[dict[str, Any]], prediction_key: str) -> dict[str, float]:
    tp = fp = tn = fn = 0

    for row in rows:
        predicted_attack = row[prediction_key] == "attack"
        actual_attack = row["label"] == "attack"

        if predicted_attack and actual_attack:
            tp += 1
        elif predicted_attack and not actual_attack:
            fp += 1
        elif not predicted_attack and actual_attack:
            fn += 1
        else:
            tn += 1

    accuracy = safe_div(tp + tn, tp + tn + fp + fn)
    precision = safe_div(tp, tp + fp)
    recall = safe_div(tp, tp + fn)
    f1 = safe_div(2 * precision * recall, precision + recall)
    fpr = safe_div(fp, fp + tn)
    fnr = safe_div(fn, fn + tp)

    return {
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "accuracy": round(accuracy, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "false_positive_rate": round(fpr, 4),
        "false_negative_rate": round(fnr, 4),
    }


def compute_latency_summary(rows: list[dict[str, Any]], key: str) -> dict[str, float]:
    values = [float(row[key]) for row in rows if row.get(key) is not None]
    if not values:
        return {"mean": 0.0, "median": 0.0, "p95": 0.0}
    return {
        "mean": round(statistics.mean(values), 3),
        "median": round(statistics.median(values), 3),
        "p95": round(percentile(values, 0.95), 3),
    }


def compute_attack_type_breakdown(rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        grouped.setdefault(row["attack_type"], []).append(row)

    breakdown: dict[str, dict[str, Any]] = {}
    for attack_type, subset in sorted(grouped.items()):
        breakdown[attack_type] = {
            "count": len(subset),
            "metrics": compute_binary_metrics(subset, "final_decision"),
        }
    return breakdown


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    if not rows:
        return
    fieldnames = list(rows[0].keys())
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def export_database_tables(db_module: Any, output_dir: Path) -> None:
    conn = db_module._get_connection()

    incidents = [dict(row) for row in conn.execute("SELECT * FROM incidents ORDER BY id").fetchall()]
    ip_rows = [
        dict(row)
        for row in conn.execute(
            "SELECT * FROM ip_reputation ORDER BY source_ip"
        ).fetchall()
    ]

    write_csv(output_dir / "incidents.csv", incidents)
    write_csv(output_dir / "ip_reputation.csv", ip_rows)


def compute_summary(
    rows: list[dict[str, Any]],
    args: argparse.Namespace,
    dataset_path: Path,
) -> dict[str, Any]:
    tier_counts = {"high": 0, "low": 0, "grey": 0}
    escalated = 0
    failures = 0

    for row in rows:
        tier_counts[row["tier"]] += 1
        if row["action_taken"] in {"block", "temp_ban", "alert"}:
            escalated += 1
        if row["evaluation_status"] != "ok":
            failures += 1

    total = len(rows)

    summary = {
        "dataset": str(dataset_path),
        "mode": "hybrid",
        "sample_count": total,
        "thresholds": {
            "high": args.high_threshold,
            "low": args.low_threshold,
        },
        "tier_counts": tier_counts,
        "tier_fraction": {
            tier: round(safe_div(count, total), 4) for tier, count in tier_counts.items()
        },
        "fraction_requiring_llm_analysis": round(safe_div(tier_counts["grey"], total), 4),
        "escalation_rate": round(safe_div(escalated, total), 4),
        "failures": failures,
        "latency_ms": {
            "inline": compute_latency_summary(rows, "inline_latency_ms"),
            "grey_zone": compute_latency_summary(
                [row for row in rows if row["tier"] == "grey"],
                "grey_zone_latency_ms",
            ),
            "total": compute_latency_summary(rows, "total_latency_ms"),
        },
        "metrics": compute_binary_metrics(rows, "final_decision"),
        "attack_type_breakdown": compute_attack_type_breakdown(rows),
    }
    return summary


def main() -> int:
    args = parse_args()
    dataset_path = Path(args.dataset).resolve()
    output_dir = Path(args.output_dir).resolve()

    ensure_output_env(output_dir, args.db_filename)

    import app.detection.detector as detector
    from app.graph.response_nodes import auto_respond, pass_through
    from app.graph.security_agent import security_agent
    from app.storage import database as db

    if not os.getenv("OPENROUTER_API_KEY"):
        raise RuntimeError(
            "Evaluation requires OPENROUTER_API_KEY so grey-zone samples can reach the LLM."
        )

    detector.HIGH_THRESHOLD = args.high_threshold
    detector.LOW_THRESHOLD = args.low_threshold
    detector.load_model()
    db.init_db()

    dataset_rows = load_dataset(dataset_path, limit=args.limit)
    results: list[dict[str, Any]] = []

    for sample in dataset_rows:
        overall_start = time.perf_counter()
        evaluation_status = "ok"
        error_message = ""
        grey_zone_latency_ms = 0.0
        llm_reasoning = ""

        http_request = detector.parse_http_request(
            method=sample["method"],
            url=sample["url"],
            headers=sample["headers"],
            body=sample["body"],
            source_ip=sample["source_ip"],
        )

        inference_start = time.perf_counter()
        confidence = float(detector.predict(http_request))
        inline_latency_ms = (time.perf_counter() - inference_start) * 1000

        if confidence >= args.high_threshold:
            tier = "high"
        elif confidence <= args.low_threshold:
            tier = "low"
        else:
            tier = "grey"

        detection_result = {
            "request_id": http_request["request_id"],
            "confidence": round(confidence, 4),
            "is_attack": tier == "high",
            "is_grey_zone": tier == "grey",
            "tier": tier,
        }

        final_decision = "pending"
        action_taken = "under_review"
        decision_source = "pending"

        try:
            if tier == "high":
                response = auto_respond(
                    {"http_request": http_request, "detection_result": detection_result}
                )["response"]
                final_decision = response["decision"]
                action_taken = response["action_taken"]
                decision_source = "model"

            elif tier == "low":
                response = pass_through(
                    {"http_request": http_request, "detection_result": detection_result}
                )["response"]
                final_decision = response["decision"]
                action_taken = response["action_taken"]
                decision_source = "model"

            else:
                db.update_ip_after_request(
                    source_ip=http_request["source_ip"],
                    is_attack=False,
                    is_grey_zone=True,
                )
                grey_start = time.perf_counter()
                security_agent.invoke(
                    {
                        "http_request": http_request,
                        "detection_result": detection_result,
                    }
                )
                grey_zone_latency_ms = (time.perf_counter() - grey_start) * 1000
                incident = db.get_incident_by_request_id(http_request["request_id"])

                if incident is None:
                    raise RuntimeError(
                        "Grey-zone LangGraph run finished without logging an incident."
                    )

                final_decision = incident["decision"]
                action_taken = incident["action_taken"]
                decision_source = incident["decision_source"]
                llm_reasoning = incident.get("llm_reasoning") or ""

        except Exception as exc:
            evaluation_status = "error"
            error_message = str(exc)

        total_latency_ms = (time.perf_counter() - overall_start) * 1000

        results.append(
            {
                "sample_id": sample["sample_id"],
                "request_id": http_request["request_id"],
                "label": sample["label"],
                "attack_type": sample["attack_type"],
                "method": sample["method"],
                "url": sample["url"],
                "source_ip": sample["source_ip"],
                "confidence": round(confidence, 4),
                "tier": tier,
                "final_decision": final_decision,
                "decision_source": decision_source,
                "action_taken": action_taken,
                "inline_latency_ms": round(inline_latency_ms, 3),
                "grey_zone_latency_ms": round(grey_zone_latency_ms, 3),
                "total_latency_ms": round(total_latency_ms, 3),
                "evaluation_status": evaluation_status,
                "error": error_message,
                "llm_reasoning": llm_reasoning,
            }
        )

    summary = compute_summary(results, args, dataset_path)

    write_csv(output_dir / "results.csv", results)
    export_database_tables(db, output_dir)
    with (output_dir / "summary.json").open("w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2)

    print(f"Evaluated {len(results)} samples from {dataset_path}")
    print(f"Results written to {output_dir}")
    print(json.dumps(summary["metrics"], indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
