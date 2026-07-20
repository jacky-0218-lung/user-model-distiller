#!/usr/bin/env python3
"""Score evidence-detector JSONL against a de-identified gold set."""

from __future__ import annotations

import argparse
import json
import math
import os
import random
import sys
import tempfile
from pathlib import Path
from typing import Any, Callable, Iterable


MAX_INPUT_BYTES = 256 * 1024 * 1024
MAX_RECORDS = 1_000_000
MAX_ID_CHARS = 512
MAX_BOOTSTRAP = 100_000
DEFAULT_BOOTSTRAP = 2_000
WILSON_Z_95 = 1.959963984540054
VERSION = "0.2.3"

GOLD_FIELDS = frozenset({"message_id", "session_id", "label", "kinds"})
GOLD_LABELS = frozenset({"positive", "negative", "ambiguous"})
DETECTOR_FIELDS = frozenset(
    {
        "schema_version",
        "session_id",
        "message_id",
        "created_at",
        "score",
        "kinds",
        "user_text",
        "context_message_id",
        "source",
        "provenance",
        "truncated",
        "review_status",
        "notice",
    }
)
DETECTOR_KINDS = frozenset({"explicit_preference", "correction", "approval"})
SUPPRESSION_REASONS = frozenset(
    {"fenced_block", "untrusted_xml", "blockquote", "role_transcript", "json_transcript"}
)
REPORT_FIELDS = frozenset(
    {"schema_version", "confusion_matrix", "metrics", "per_kind_recall", "bootstrap"}
)
COUNT_FIELDS = frozenset(
    {
        "tp",
        "fp",
        "fn",
        "tn",
        "gold_positive",
        "gold_negative",
        "gold_ambiguous",
        "detected_ambiguous",
        "detected_total",
    }
)
METRIC_FIELDS = frozenset({"precision", "recall", "f1", "specificity", "sensitive_leakage"})
RATE_FIELDS = frozenset({"value", "numerator", "denominator", "wilson_95", "bootstrap_95"})
INTERVAL_FIELDS = frozenset({"low", "high"})
KIND_RATE_FIELDS = frozenset(
    {"value", "detected_positive", "gold_positive", "wilson_95", "bootstrap_95"}
)
BOOTSTRAP_FIELDS = frozenset({"unit", "samples", "seed", "confidence"})


class EvaluationError(ValueError):
    """Raised for invalid inputs or non-evaluable reports."""


def _closed_object(value: Any, fields: frozenset[str], context: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise EvaluationError(f"{context} must be an object")
    actual = set(value)
    if actual != fields:
        missing = sorted(fields - actual)
        extra = sorted(actual - fields)
        details: list[str] = []
        if missing:
            details.append(f"missing fields {missing}")
        if extra:
            details.append(f"unexpected fields {extra}")
        raise EvaluationError(f"{context} has invalid schema: {', '.join(details)}")
    return value


def _identifier(value: Any, context: str) -> str:
    if not isinstance(value, str) or not value or len(value) > MAX_ID_CHARS:
        raise EvaluationError(f"{context} must be a non-empty string of at most {MAX_ID_CHARS} characters")
    return value


def _string_list(
    value: Any,
    context: str,
    *,
    allowed: frozenset[str] | None = None,
) -> list[str]:
    if not isinstance(value, list):
        raise EvaluationError(f"{context} must be an array")
    result: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item:
            raise EvaluationError(f"{context}[{index}] must be a non-empty string")
        if allowed is not None and item not in allowed:
            raise EvaluationError(f"{context}[{index}] has unsupported value {item!r}")
        result.append(item)
    if len(set(result)) != len(result):
        raise EvaluationError(f"{context} must not contain duplicates")
    return result


def _no_duplicate_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise EvaluationError(f"duplicate JSON field {key!r}")
        result[key] = value
    return result


def read_jsonl(path: Path, validator: Callable[[Any, int], dict[str, Any]]) -> list[dict[str, Any]]:
    if path.is_symlink():
        raise EvaluationError(f"Refusing symbolic link input: {path}")
    if not path.is_file():
        raise EvaluationError(f"Input does not exist: {path}")
    if path.stat().st_size > MAX_INPUT_BYTES:
        raise EvaluationError("Input exceeds size limit")
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8-sig") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            if len(rows) >= MAX_RECORDS:
                raise EvaluationError("Input exceeds record limit")
            try:
                raw = json.loads(line, object_pairs_hook=_no_duplicate_object)
            except json.JSONDecodeError as exc:
                raise EvaluationError(f"Invalid JSON at line {line_number}: {exc.msg}") from exc
            rows.append(validator(raw, line_number))
    return rows


def validate_gold(raw: Any, line_number: int) -> dict[str, Any]:
    row = _closed_object(raw, GOLD_FIELDS, f"gold line {line_number}")
    _identifier(row["message_id"], f"gold line {line_number} message_id")
    _identifier(row["session_id"], f"gold line {line_number} session_id")
    if row["label"] not in GOLD_LABELS:
        raise EvaluationError(f"gold line {line_number} has invalid label")
    _string_list(row["kinds"], f"gold line {line_number} kinds")
    return row


def validate_detector(raw: Any, line_number: int) -> dict[str, Any]:
    row = _closed_object(raw, DETECTOR_FIELDS, f"detector line {line_number}")
    if row["schema_version"] != "1.0":
        raise EvaluationError(f"detector line {line_number} has unsupported schema_version")
    _identifier(row["message_id"], f"detector line {line_number} message_id")
    _identifier(row["session_id"], f"detector line {line_number} session_id")
    if row["created_at"] is not None and not isinstance(row["created_at"], str):
        raise EvaluationError(f"detector line {line_number} created_at must be a string or null")
    if type(row["score"]) is not int or row["score"] < 0:
        raise EvaluationError(f"detector line {line_number} score must be a non-negative integer")
    _string_list(row["kinds"], f"detector line {line_number} kinds", allowed=DETECTOR_KINDS)
    if not row["kinds"]:
        raise EvaluationError(f"detector line {line_number} kinds must not be empty")
    if not isinstance(row["user_text"], str):
        raise EvaluationError(f"detector line {line_number} user_text must be a string")
    if row["context_message_id"] is not None:
        _identifier(row["context_message_id"], f"detector line {line_number} context_message_id")

    if row["source"] is not None:
        source = _closed_object(
            row["source"], frozenset({"id", "sha256"}), f"detector line {line_number} source"
        )
        _identifier(source["id"], f"detector line {line_number} source.id")
        if (
            not isinstance(source["sha256"], str)
            or len(source["sha256"]) != 64
            or any(character not in "0123456789abcdef" for character in source["sha256"])
        ):
            raise EvaluationError(f"detector line {line_number} source.sha256 must be lowercase SHA-256 hex")

    provenance = _closed_object(
        row["provenance"],
        frozenset({"role", "direct", "suppressed_envelopes"}),
        f"detector line {line_number} provenance",
    )
    if provenance["role"] != "user" or provenance["direct"] is not True:
        raise EvaluationError(f"detector line {line_number} provenance must identify direct user evidence")
    _string_list(
        provenance["suppressed_envelopes"],
        f"detector line {line_number} provenance.suppressed_envelopes",
        allowed=SUPPRESSION_REASONS,
    )
    if type(row["truncated"]) is not bool:
        raise EvaluationError(f"detector line {line_number} truncated must be a boolean")
    expected_status = "needs_full_review" if row["truncated"] else "unreviewed"
    if row["review_status"] != expected_status:
        raise EvaluationError(f"detector line {line_number} review_status does not match truncated")
    if row["notice"] != "Candidate evidence only. Do not activate without user review.":
        raise EvaluationError(f"detector line {line_number} has invalid notice")
    return row


def validate_scope(gold: list[dict[str, Any]], detector: list[dict[str, Any]]) -> None:
    gold_by_id: dict[str, dict[str, Any]] = {}
    for row in gold:
        message_id = row["message_id"]
        if message_id in gold_by_id:
            raise EvaluationError("gold message_id values must be unique")
        gold_by_id[message_id] = row

    detector_ids: set[str] = set()
    for row in detector:
        message_id = row["message_id"]
        if message_id in detector_ids:
            raise EvaluationError("detector message_id values must be unique")
        detector_ids.add(message_id)
        gold_row = gold_by_id.get(message_id)
        if gold_row is None:
            raise EvaluationError("detector contains a message_id outside the gold scope")
        if row["session_id"] != gold_row["session_id"]:
            raise EvaluationError("detector session_id does not match the gold scope")


def ratio(numerator: int, denominator: int, *, empty: float | None = None) -> float | None:
    return numerator / denominator if denominator else empty


def wilson_95(successes: int, total: int) -> dict[str, float] | None:
    if total == 0:
        return None
    proportion = successes / total
    z2 = WILSON_Z_95 * WILSON_Z_95
    denominator = 1.0 + z2 / total
    center = (proportion + z2 / (2.0 * total)) / denominator
    margin = (
        WILSON_Z_95
        * math.sqrt((proportion * (1.0 - proportion) + z2 / (4.0 * total)) / total)
        / denominator
    )
    return {"low": max(0.0, center - margin), "high": min(1.0, center + margin)}


def _percentile(values: list[float], quantile: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    if ordered[0] == ordered[-1]:
        return ordered[0]
    position = (len(ordered) - 1) * quantile
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    fraction = position - lower
    return ordered[lower] * (1.0 - fraction) + ordered[upper] * fraction


def _bootstrap_interval(values: list[float]) -> dict[str, float] | None:
    low = _percentile(values, 0.025)
    high = _percentile(values, 0.975)
    if low is None or high is None:
        return None
    return {"low": min(low, high), "high": max(low, high)}


def _row_counts(row: dict[str, Any], detected: bool, positive_kinds: tuple[str, ...]) -> dict[str, Any]:
    label = row["label"]
    return {
        "tp": int(label == "positive" and detected),
        "fp": int(label == "negative" and detected),
        "fn": int(label == "positive" and not detected),
        "tn": int(label == "negative" and not detected),
        "sensitive_detected": int("sensitive" in row["kinds"] and detected),
        "sensitive_total": int("sensitive" in row["kinds"]),
        "kind_detected": {
            kind: int(label == "positive" and kind in row["kinds"] and detected)
            for kind in positive_kinds
        },
        "kind_total": {
            kind: int(label == "positive" and kind in row["kinds"])
            for kind in positive_kinds
        },
    }


def _sum_counts(items: Iterable[dict[str, Any]], positive_kinds: tuple[str, ...]) -> dict[str, Any]:
    total: dict[str, Any] = {
        "tp": 0,
        "fp": 0,
        "fn": 0,
        "tn": 0,
        "sensitive_detected": 0,
        "sensitive_total": 0,
        "kind_detected": {kind: 0 for kind in positive_kinds},
        "kind_total": {kind: 0 for kind in positive_kinds},
    }
    for item in items:
        for name in ("tp", "fp", "fn", "tn", "sensitive_detected", "sensitive_total"):
            total[name] += item[name]
        for kind in positive_kinds:
            total["kind_detected"][kind] += item["kind_detected"][kind]
            total["kind_total"][kind] += item["kind_total"][kind]
    return total


def _metric_values(counts: dict[str, Any]) -> dict[str, float | None]:
    tp, fp, fn, tn = (counts[name] for name in ("tp", "fp", "fn", "tn"))
    precision = ratio(tp, tp + fp)
    recall = ratio(tp, tp + fn)
    return {
        "precision": precision,
        "recall": recall,
        "f1": ratio(2 * tp, 2 * tp + fp + fn),
        "specificity": ratio(tn, tn + fp),
        "sensitive_leakage": ratio(
            counts["sensitive_detected"], counts["sensitive_total"], empty=0.0
        ),
    }


def _bootstrap(
    session_counts: list[dict[str, Any]],
    positive_kinds: tuple[str, ...],
    samples: int,
    seed: int,
) -> tuple[dict[str, dict[str, float] | None], dict[str, dict[str, float] | None]]:
    metric_samples: dict[str, list[float]] = {name: [] for name in METRIC_FIELDS}
    kind_samples: dict[str, list[float]] = {kind: [] for kind in positive_kinds}
    if session_counts:
        generator = random.Random(seed)
        session_count = len(session_counts)
        for _ in range(samples):
            sampled = (session_counts[generator.randrange(session_count)] for _ in range(session_count))
            counts = _sum_counts(sampled, positive_kinds)
            for name, value in _metric_values(counts).items():
                if value is not None and not (
                    name == "sensitive_leakage" and counts["sensitive_total"] == 0
                ):
                    metric_samples[name].append(value)
            for kind in positive_kinds:
                value = ratio(counts["kind_detected"][kind], counts["kind_total"][kind])
                if value is not None:
                    kind_samples[kind].append(value)
    return (
        {name: _bootstrap_interval(values) for name, values in metric_samples.items()},
        {kind: _bootstrap_interval(values) for kind, values in kind_samples.items()},
    )


def build_report(
    gold: list[dict[str, Any]],
    detector: list[dict[str, Any]],
    *,
    seed: int,
    bootstrap_samples: int,
) -> dict[str, Any]:
    validate_scope(gold, detector)
    detected_ids = {row["message_id"] for row in detector}
    positive_kinds = tuple(
        sorted({kind for row in gold if row["label"] == "positive" for kind in row["kinds"]})
    )

    rows_with_counts = [
        (row, _row_counts(row, row["message_id"] in detected_ids, positive_kinds)) for row in gold
    ]
    counts = _sum_counts((item for _, item in rows_with_counts), positive_kinds)
    by_session: dict[str, list[dict[str, Any]]] = {}
    for row, item in rows_with_counts:
        by_session.setdefault(row["session_id"], []).append(item)
    session_counts = [_sum_counts(items, positive_kinds) for items in by_session.values()]
    bootstrap_metrics, bootstrap_kinds = _bootstrap(
        session_counts, positive_kinds, bootstrap_samples, seed
    )

    tp, fp, fn, tn = (counts[name] for name in ("tp", "fp", "fn", "tn"))
    metric_values = _metric_values(counts)
    fractions = {
        "precision": (tp, tp + fp),
        "recall": (tp, tp + fn),
        "f1": (2 * tp, 2 * tp + fp + fn),
        "specificity": (tn, tn + fp),
        "sensitive_leakage": (counts["sensitive_detected"], counts["sensitive_total"]),
    }
    metrics: dict[str, dict[str, Any]] = {}
    for name in ("precision", "recall", "f1", "specificity", "sensitive_leakage"):
        numerator, denominator = fractions[name]
        metrics[name] = {
            "value": metric_values[name],
            "numerator": numerator,
            "denominator": denominator,
            "wilson_95": wilson_95(numerator, denominator),
            "bootstrap_95": bootstrap_metrics[name],
        }

    per_kind = {
        kind: {
            "value": ratio(counts["kind_detected"][kind], counts["kind_total"][kind]),
            "detected_positive": counts["kind_detected"][kind],
            "gold_positive": counts["kind_total"][kind],
            "wilson_95": wilson_95(counts["kind_detected"][kind], counts["kind_total"][kind]),
            "bootstrap_95": bootstrap_kinds[kind],
        }
        for kind in positive_kinds
    }
    return {
        "schema_version": "1.0",
        "confusion_matrix": {
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "tn": tn,
            "gold_positive": tp + fn,
            "gold_negative": fp + tn,
            "gold_ambiguous": sum(row["label"] == "ambiguous" for row in gold),
            "detected_ambiguous": sum(
                row["label"] == "ambiguous" and row["message_id"] in detected_ids for row in gold
            ),
            "detected_total": len(detector),
        },
        "metrics": metrics,
        "per_kind_recall": per_kind,
        "bootstrap": {
            "unit": "session",
            "samples": bootstrap_samples,
            "seed": seed,
            "confidence": 0.95,
        },
    }


def atomic_write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_name = ""
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            delete=False,
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
        ) as handle:
            temp_name = handle.name
            json.dump(value, handle, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, path)
        try:
            path.chmod(0o600)
        except OSError:
            pass
    finally:
        if temp_name and os.path.exists(temp_name):
            try:
                os.unlink(temp_name)
            except OSError:
                pass


def _validate_interval(value: Any, context: str) -> None:
    if value is None:
        return
    interval = _closed_object(value, INTERVAL_FIELDS, context)
    for name in ("low", "high"):
        number = interval[name]
        if type(number) not in {int, float} or not math.isfinite(number) or not 0.0 <= number <= 1.0:
            raise EvaluationError(f"{context}.{name} must be between zero and one")
    if interval["low"] > interval["high"]:
        raise EvaluationError(f"{context} bounds are reversed")


def _validate_rate(value: Any, context: str, fields: frozenset[str] = RATE_FIELDS) -> None:
    rate = _closed_object(value, fields, context)
    metric = rate["value"]
    if metric is not None and (
        type(metric) not in {int, float} or not math.isfinite(metric) or not 0.0 <= metric <= 1.0
    ):
        raise EvaluationError(f"{context}.value must be null or between zero and one")
    count_fields = (
        ("numerator", "denominator") if fields == RATE_FIELDS else ("detected_positive", "gold_positive")
    )
    for name in count_fields:
        if type(rate[name]) is not int or rate[name] < 0:
            raise EvaluationError(f"{context}.{name} must be a non-negative integer")
    numerator, denominator = (rate[name] for name in count_fields)
    if numerator > denominator:
        raise EvaluationError(f"{context} numerator must not exceed its denominator")
    expected_value = ratio(numerator, denominator)
    if metric != expected_value:
        raise EvaluationError(f"{context}.value is inconsistent with its counts")
    expected_wilson = wilson_95(numerator, denominator)
    if rate["wilson_95"] != expected_wilson:
        raise EvaluationError(f"{context}.wilson_95 is inconsistent with its counts")
    _validate_interval(rate["wilson_95"], f"{context}.wilson_95")
    _validate_interval(rate["bootstrap_95"], f"{context}.bootstrap_95")


def read_report(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_INPUT_BYTES:
        raise EvaluationError("Report does not exist, is linked, or exceeds the size limit")
    try:
        with path.open("r", encoding="utf-8-sig") as handle:
            raw = json.load(handle, object_pairs_hook=_no_duplicate_object)
    except json.JSONDecodeError as exc:
        raise EvaluationError(f"Invalid report JSON: {exc.msg}") from exc
    report = _closed_object(raw, REPORT_FIELDS, "report")
    if report["schema_version"] != "1.0":
        raise EvaluationError("report has unsupported schema_version")
    counts = _closed_object(report["confusion_matrix"], COUNT_FIELDS, "report.confusion_matrix")
    if any(type(value) is not int or value < 0 for value in counts.values()):
        raise EvaluationError("report confusion counts must be non-negative integers")
    if counts["gold_positive"] != counts["tp"] + counts["fn"]:
        raise EvaluationError("report positive counts are inconsistent")
    if counts["gold_negative"] != counts["fp"] + counts["tn"]:
        raise EvaluationError("report negative counts are inconsistent")
    if counts["detected_ambiguous"] > counts["gold_ambiguous"]:
        raise EvaluationError("report ambiguous counts are inconsistent")
    if counts["detected_total"] != counts["tp"] + counts["fp"] + counts["detected_ambiguous"]:
        raise EvaluationError("report detected counts are inconsistent")
    metrics = _closed_object(report["metrics"], METRIC_FIELDS, "report.metrics")
    for name, value in metrics.items():
        if name == "sensitive_leakage" and value.get("denominator") == 0 and value.get("value") == 0.0:
            adjusted = dict(value)
            adjusted["value"] = None
            _validate_rate(adjusted, f"report.metrics.{name}")
        else:
            _validate_rate(value, f"report.metrics.{name}")
    expected_fractions = {
        "precision": (counts["tp"], counts["tp"] + counts["fp"]),
        "recall": (counts["tp"], counts["tp"] + counts["fn"]),
        "f1": (2 * counts["tp"], 2 * counts["tp"] + counts["fp"] + counts["fn"]),
        "specificity": (counts["tn"], counts["tn"] + counts["fp"]),
    }
    for name, (numerator, denominator) in expected_fractions.items():
        metric = metrics[name]
        if metric["numerator"] != numerator or metric["denominator"] != denominator:
            raise EvaluationError(f"report.metrics.{name} counts are inconsistent with the confusion matrix")
    if not isinstance(report["per_kind_recall"], dict):
        raise EvaluationError("report.per_kind_recall must be an object")
    for kind, value in report["per_kind_recall"].items():
        if not isinstance(kind, str) or not kind:
            raise EvaluationError("report per-kind names must be non-empty strings")
        _validate_rate(value, f"report.per_kind_recall.{kind}", KIND_RATE_FIELDS)
    bootstrap = _closed_object(report["bootstrap"], BOOTSTRAP_FIELDS, "report.bootstrap")
    if bootstrap["unit"] != "session":
        raise EvaluationError("report bootstrap unit must be session")
    if type(bootstrap["samples"]) is not int or not 1 <= bootstrap["samples"] <= MAX_BOOTSTRAP:
        raise EvaluationError("report bootstrap samples are invalid")
    if type(bootstrap["seed"]) is not int:
        raise EvaluationError("report bootstrap seed must be an integer")
    if bootstrap["confidence"] != 0.95:
        raise EvaluationError("report bootstrap confidence must be 0.95")
    return report


def _threshold(value: str) -> float:
    try:
        number = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a number between zero and one") from exc
    if not math.isfinite(number) or not 0.0 <= number <= 1.0:
        raise argparse.ArgumentTypeError("must be a number between zero and one")
    return number


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    score = subparsers.add_parser("score", help="score detector JSONL against gold JSONL")
    score.add_argument("gold", type=Path)
    score.add_argument("detector", type=Path)
    score.add_argument("--output", required=True, type=Path)
    score.add_argument("--seed", type=int, default=0)
    score.add_argument("--bootstrap", type=int, default=DEFAULT_BOOTSTRAP)

    gate = subparsers.add_parser("gate", help="apply release thresholds to a score report")
    gate.add_argument("report", type=Path)
    gate.add_argument("--min-precision", required=True, type=_threshold)
    gate.add_argument("--min-recall", required=True, type=_threshold)
    gate.add_argument(
        "--max-sensitive-leakage",
        required=True,
        type=_threshold,
        help="maximum detection rate for gold rows whose kinds include 'sensitive'",
    )
    return parser


def _run_score(args: argparse.Namespace) -> int:
    if not 1 <= args.bootstrap <= MAX_BOOTSTRAP:
        raise EvaluationError(f"--bootstrap must be between 1 and {MAX_BOOTSTRAP}")
    gold = read_jsonl(args.gold.resolve(), validate_gold)
    detector = read_jsonl(args.detector.resolve(), validate_detector)
    report = build_report(gold, detector, seed=args.seed, bootstrap_samples=args.bootstrap)
    atomic_write_json(args.output.resolve(), report)
    print(json.dumps({"status": "scored", "output": str(args.output)}, ensure_ascii=False))
    return 0


def _run_gate(args: argparse.Namespace) -> int:
    report = read_report(args.report.resolve())
    failures: list[str] = []
    precision = report["metrics"]["precision"]["value"]
    recall = report["metrics"]["recall"]["value"]
    leakage = report["metrics"]["sensitive_leakage"]["value"]
    if precision is None or precision < args.min_precision:
        failures.append("precision")
    if report["confusion_matrix"]["gold_positive"] == 0 or recall is None:
        failures.append("recall (non-evaluable: no gold positives)")
    elif recall < args.min_recall:
        failures.append("recall")
    if leakage is None or leakage > args.max_sensitive_leakage:
        failures.append("sensitive_leakage")
    if failures:
        print(json.dumps({"status": "failed", "failed_gates": failures}, separators=(",", ":")))
        return 1
    print(json.dumps({"status": "passed"}, separators=(",", ":")))
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "score":
            return _run_score(args)
        return _run_gate(args)
    except (OSError, EvaluationError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
