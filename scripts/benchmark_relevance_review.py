"""Evaluate a manually labelled synthetic seed; live inference is explicitly opt-in.

Run with ``python -m scripts.benchmark_relevance_review --output /tmp/relevance.json``.
Add ``--live`` to send only the fixture text to the configured LM Studio server.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import time

from osint.llm_review import PROMPT_VERSION, RelevanceReviewer, review_source
from osint.models import NormalizedTarget
from osint.target_profile import build_target_profile

DEFAULT_CASES = Path(__file__).resolve().parents[1] / "benchmarks" / "relevance_seed.json"
LABELS = ("relevant", "unrelated", "uncertain")


def prepare_case(case):
    target = NormalizedTarget(case["domain"], case["domain"], "https://" + case["domain"], case["brand"])
    profile = build_target_profile(target, case.get("observations", []))
    # Repetition is only a fixture convenience for testing late references.
    prefix = case.get("prefix", "") * min(max(int(case.get("prefix_repeat", 1)), 0), 2000)
    text = prefix + case["text"] + case.get("suffix", "")
    source = review_source(case["url"], case.get("title", ""), text,
                           kind=case.get("kind", "page_excerpt"), source_ref="benchmark:" + case["id"],
                           target=target, profile=profile)
    if case.get("label") not in LABELS or source is None:
        raise ValueError("Invalid labelled fixture: " + str(case.get("id")))
    return target, profile, source


def summarize(rows):
    matrix = {label: dict.fromkeys((*LABELS, "unavailable", "not_run"), 0) for label in LABELS}
    for row in rows:
        matrix[row["expected"]][row["prediction"]] += 1
    available = sum(row["prediction"] in LABELS for row in rows)
    attempted = sum(row["prediction"] != "not_run" for row in rows)
    tp = matrix["relevant"]["relevant"]
    predicted_positive = sum(counts["relevant"] for counts in matrix.values())
    actual_positive = sum(matrix["relevant"].values())
    return {
        "cases": len(rows), "attempted": attempted, "valid_reviews": available,
        "availability": available / attempted if attempted else None,
        "review_coverage": attempted / len(rows) if rows else None,
        "relevant_precision": tp / predicted_positive if predicted_positive else None,
        "relevant_recall_including_unavailable_and_unreviewed": tp / actual_positive if attempted and actual_positive else None,
        "accuracy_on_valid_reviews": sum(matrix[x][x] for x in LABELS) / available if available else None,
        "uncertain_reviews": sum(counts["uncertain"] for counts in matrix.values()),
        "confusion_matrix": matrix,
    }


def evaluate(cases, *, live=False, seconds=300, reviewer=None):
    started = time.monotonic()
    reviewer = reviewer or (RelevanceReviewer() if live else None)
    rows = []
    consecutive_failures = 0
    for case in cases:
        target, profile, source = prepare_case(case)
        row = {"id": case["id"], "category": case["category"], "expected": case["label"],
               "label_reason": case["label_reason"], "prediction": "not_run", "source": source,
               "target_profile": profile}
        remaining = seconds - (time.monotonic() - started)
        if live and remaining > 0 and consecutive_failures < 2:
            try:
                review = reviewer.review(target, source, min(reviewer.timeout, remaining), profile=profile)
                row["prediction"] = review["relevance"]
                row["review"] = review
                consecutive_failures = 0
            except Exception as exc:
                consecutive_failures += 1
                row["prediction"] = "unavailable"
                row["error"] = str(exc)[:200] if isinstance(exc, ValueError) else type(exc).__name__
        elif live:
            row["skip_reason"] = "server_failure_limit" if consecutive_failures >= 2 else "time_budget"
        rows.append(row)
    return {
        "dataset_type": "manually_labelled_synthetic_seed",
        "limitation": "Synthetic examples test specific failure modes; these scores do not establish production accuracy or web-search recall.",
        "mode": "live" if live else "passage_selection_only",
        "prompt_version": PROMPT_VERSION,
        "requested_model": reviewer.model if reviewer else None,
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "category_counts": dict(Counter(row["category"] for row in rows)),
        "metrics": summarize(rows), "cases": rows,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cases", type=Path, default=DEFAULT_CASES)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--live", action="store_true", help="Send synthetic fixture text to the configured LM Studio server.")
    parser.add_argument("--limit", type=int, default=30)
    parser.add_argument("--seconds", type=float, default=300)
    args = parser.parse_args()
    if not 1 <= args.limit <= 200 or not 1 <= args.seconds <= 600:
        parser.error("--limit must be 1..200 and --seconds 1..600")
    raw = args.cases.read_bytes()
    cases = json.loads(raw)
    if not isinstance(cases, list) or len({case["id"] for case in cases}) != len(cases):
        parser.error("The dataset must be a list of cases with unique IDs")
    result = evaluate(cases[:args.limit], live=args.live, seconds=args.seconds)
    result["dataset_sha256"] = hashlib.sha256(raw).hexdigest()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n")
    print(json.dumps({"mode": result["mode"], "output": str(args.output), "metrics": result["metrics"]}, indent=2))


if __name__ == "__main__":
    main()
