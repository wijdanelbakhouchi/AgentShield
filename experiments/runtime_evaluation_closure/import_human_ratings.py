"""Import ratings returned by the standalone public scoring app.

This module is private to the AgentShield repository.  It validates the
blinded evaluator export, writes a ratings file that the local scoring page
can read, and creates a separate private joined artifact for analysis.  The
hidden configuration mapping is loaded only from the private repaired raw
artifact and is never copied into the public package or the public export.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import tempfile
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import QUALITY_DATASET, QUALITY_OUTPUT


DIMENSIONS = ("task_success", "relevance", "completeness", "factuality", "helpfulness")
LABELS = ("A", "B")
REPAIRED_RAW = QUALITY_OUTPUT / "quality_results_repaired.jsonl"
RATING_SCHEMA = "phase16.5-remote-human-ratings-v1"
EVALUATOR_VERSION = "phase16.5-human-rating-remote-v1"


class RatingImportError(ValueError):
    """Raised when an evaluator export fails validation."""


def _expected_task_ids() -> list[str]:
    value = json.loads(QUALITY_DATASET.read_text(encoding="utf-8"))
    if not isinstance(value, list) or len(value) != 12:
        raise RatingImportError("Frozen quality dataset must contain exactly 12 tasks")
    ids = [str(row.get("task_id", "")) for row in value if isinstance(row, Mapping)]
    if len(ids) != 12 or len(set(ids)) != 12 or any(not task_id for task_id in ids):
        raise RatingImportError("Frozen quality dataset contains invalid or duplicate task IDs")
    return ids


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        value = json.loads(line)
        if not isinstance(value, dict):
            raise RatingImportError(f"Expected an object at {path}:{line_number}")
        rows.append(value)
    return rows


def _load_private_mapping(expected_ids: list[str]) -> dict[tuple[str, str], str]:
    if not REPAIRED_RAW.exists():
        raise RatingImportError(f"Missing private blind mapping artifact: {REPAIRED_RAW}")
    mapping: dict[tuple[str, str], str] = {}
    for row in _read_jsonl(REPAIRED_RAW):
        task_id = str(row.get("sample_id", ""))
        label = str(row.get("blind_label", ""))
        configuration = str(row.get("configuration", ""))
        key = (task_id, label)
        if task_id not in expected_ids or label not in LABELS or not configuration:
            raise RatingImportError("Private blind mapping contains an unexpected record")
        if key in mapping:
            raise RatingImportError(f"Private blind mapping contains duplicate {task_id}/{label}")
        mapping[key] = configuration
    expected_pairs = {(task_id, label) for task_id in expected_ids for label in LABELS}
    if set(mapping) != expected_pairs:
        raise RatingImportError("Private blind mapping must contain exactly 24 task/label pairs")
    return mapping


def _score(value: Any, where: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value not in {1, 2, 3, 4, 5}:
        raise RatingImportError(f"{where} must be an integer score from 1 to 5")
    return value


def _notes(value: Any, where: str) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        raise RatingImportError(f"{where} must be text")
    return value


def _normalise_record(record: Mapping[str, Any], expected_ids: set[str], row_number: int) -> dict[str, Any]:
    allowed = {"task_id", "A", "B", "A_notes", "B_notes"}
    if set(record) != allowed:
        raise RatingImportError(f"JSON rating record {row_number} must contain only task_id, A, B, A_notes, B_notes")
    task_id = str(record.get("task_id", ""))
    if task_id not in expected_ids:
        raise RatingImportError(f"Unknown task_id in rating record {row_number}: {task_id}")
    result: dict[str, Any] = {"task_id": task_id}
    for label in LABELS:
        scores = record.get(label)
        if not isinstance(scores, Mapping) or set(scores) != set(DIMENSIONS):
            raise RatingImportError(f"{task_id}/{label} must contain exactly the five scoring dimensions")
        result[label] = {dimension: _score(scores[dimension], f"{task_id}/{label}/{dimension}") for dimension in DIMENSIONS}
    result["A_notes"] = _notes(record.get("A_notes"), f"{task_id}/A_notes")
    result["B_notes"] = _notes(record.get("B_notes"), f"{task_id}/B_notes")
    return result


def _load_json_ratings(path: Path, expected_ids: list[str]) -> list[dict[str, Any]]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(value, Mapping):
        if "ratings" not in value or not isinstance(value["ratings"], list):
            raise RatingImportError("JSON export must contain a ratings list")
        rows = value["ratings"]
        if "schema_version" in value and value["schema_version"] != RATING_SCHEMA:
            raise RatingImportError(f"Unsupported ratings schema: {value['schema_version']}")
    elif isinstance(value, list):
        rows = value
    else:
        raise RatingImportError("JSON export must be an object with ratings or a list")
    if not rows:
        raise RatingImportError("Ratings export is empty")
    normalised = [_normalise_record(row, set(expected_ids), index) if isinstance(row, Mapping) else _bad_record(index) for index, row in enumerate(rows, 1)]
    return _reject_duplicates(normalised)


def _bad_record(row_number: int) -> dict[str, Any]:
    raise RatingImportError(f"JSON rating record {row_number} must be an object")


def _load_csv_ratings(path: Path, expected_ids: list[str]) -> list[dict[str, Any]]:
    required = {"task_id", "A_notes", "B_notes", *(f"{label}_{dimension}" for label in LABELS for dimension in DIMENSIONS)}
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        fields = set(reader.fieldnames or [])
        if fields != required:
            missing = sorted(required - fields)
            extra = sorted(fields - required)
            raise RatingImportError(f"CSV columns mismatch (missing={missing}, extra={extra})")
        rows: list[dict[str, Any]] = []
        for row_number, row in enumerate(reader, 2):
            task_id = str(row.get("task_id", ""))
            if task_id not in set(expected_ids):
                raise RatingImportError(f"Unknown task_id in CSV row {row_number}: {task_id}")
            converted: dict[str, Any] = {"task_id": task_id, "A_notes": row.get("A_notes", ""), "B_notes": row.get("B_notes", "")}
            for label in LABELS:
                converted[label] = {
                    dimension: _score(_parse_csv_score(row.get(f"{label}_{dimension}"), f"{task_id}/{label}/{dimension}"), f"{task_id}/{label}/{dimension}")
                    for dimension in DIMENSIONS
                }
            rows.append(_normalise_record(converted, set(expected_ids), row_number))
    if not rows:
        raise RatingImportError("Ratings CSV is empty")
    return _reject_duplicates(rows)


def _parse_csv_score(value: str | None, where: str) -> int:
    if value is None or not value.strip():
        raise RatingImportError(f"{where} must be an integer score from 1 to 5")
    try:
        return int(value)
    except ValueError as exc:
        raise RatingImportError(f"{where} must be an integer score from 1 to 5") from exc


def _reject_duplicates(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    for row in rows:
        task_id = row["task_id"]
        if task_id in seen:
            raise RatingImportError(f"Duplicate ratings for task_id: {task_id}")
        seen.add(task_id)
    return rows


def _atomic_write_jsonl(path: Path, rows: list[dict[str, Any]], overwrite: bool) -> None:
    if path.exists() and not overwrite:
        raise RatingImportError(f"Refusing to overwrite existing output; pass --overwrite: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            for row in rows:
                handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
        Path(temporary_name).replace(path)
    finally:
        temporary = Path(temporary_name)
        if temporary.exists():
            temporary.unlink()


def import_ratings(input_path: Path, output_path: Path, joined_path: Path, overwrite: bool = False) -> tuple[int, int]:
    expected_ids = _expected_task_ids()
    mapping = _load_private_mapping(expected_ids)
    if input_path.suffix.casefold() == ".csv":
        rows = _load_csv_ratings(input_path, expected_ids)
    else:
        rows = _load_json_ratings(input_path, expected_ids)

    timestamp = datetime.now(timezone.utc).isoformat()
    ratings_rows: list[dict[str, Any]] = []
    joined_rows: list[dict[str, Any]] = []
    for row in sorted(rows, key=lambda item: expected_ids.index(item["task_id"])):
        for label in LABELS:
            rating = {
                "sample_id": row["task_id"],
                "blind_label": label,
                **row[label],
                "notes": row[f"{label}_notes"],
                "rated_at": timestamp,
                "rubric_scale": "1=very poor/failed; 2=poor; 3=acceptable; 4=good; 5=excellent",
                "evaluator_version": EVALUATOR_VERSION,
            }
            ratings_rows.append(rating)
            joined_rows.append({**rating, "configuration": mapping[(row["task_id"], label)]})
    _atomic_write_jsonl(output_path, ratings_rows, overwrite)
    _atomic_write_jsonl(joined_path, joined_rows, overwrite)
    return len(rows), len(ratings_rows)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Import a remote blinded human-quality ratings export")
    parser.add_argument("input", type=Path, help="Returned human_ratings.json or human_ratings.csv")
    parser.add_argument("--output", type=Path, default=QUALITY_OUTPUT / "human_ratings.jsonl")
    parser.add_argument("--joined-output", type=Path, default=QUALITY_OUTPUT / "human_ratings_joined.jsonl")
    parser.add_argument("--overwrite", action="store_true", help="Allow replacing the two requested output files")
    args = parser.parse_args(argv)
    try:
        pairs, responses = import_ratings(args.input, args.output, args.joined_output, args.overwrite)
    except (OSError, json.JSONDecodeError, csv.Error, RatingImportError) as exc:
        parser.error(str(exc))
    print(f"Imported {pairs} task pairs / {responses} response ratings")
    print(f"Ratings output: {args.output}")
    print(f"Private joined output: {args.joined_output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
