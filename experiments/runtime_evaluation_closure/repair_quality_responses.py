"""Repair only empty provider-backed quality responses.

The original quality artifact is intentionally read-only.  This module makes
one bounded smoke completion for the first missing record, then one completion
for each remaining missing record, and writes versioned repaired artifacts.
It never changes the frozen task dataset or the AgentShield security
configuration.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import uuid
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from experiments.performance_quality.run_quality import blinded_order
from providers.service import ProviderInvocationError, ProviderService

from .config import QUALITY_DATASET, QUALITY_OUTPUT


MODEL = "openai/gpt-oss-20b"
PROVIDER = "groq"
SEED = 20250916
REPAIRED_TOKEN_BUDGET = 4096
REGENERATION_REASON = "empty completion / insufficient token budget"
ORIGINAL_RAW = QUALITY_OUTPUT / "quality_results.jsonl"
ORIGINAL_BLIND = QUALITY_OUTPUT / "quality_blind_scoring.jsonl"
REPAIRED_RAW = QUALITY_OUTPUT / "quality_results_repaired.jsonl"
REPAIRED_BLIND = QUALITY_OUTPUT / "quality_blind_scoring_repaired.jsonl"
REPAIRED_SUMMARY = QUALITY_OUTPUT / "quality_summary_repaired.json"
CHECKPOINT = QUALITY_OUTPUT / "quality_results_repair_checkpoint.jsonl"


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        raise FileNotFoundError(path)
    rows: list[dict[str, Any]] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        value = json.loads(line)
        if not isinstance(value, dict):
            raise ValueError(f"Expected JSON object at {path}:{line_number}")
        rows.append(value)
    return rows


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        "".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
        newline="\n",
    )
    temporary.replace(path)


def _write_json(path: Path, value: Mapping[str, Any]) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _message_text(value: Any) -> str:
    content = getattr(value, "content", value)
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        pieces: list[str] = []
        for item in content:
            if isinstance(item, str):
                pieces.append(item)
            elif isinstance(item, Mapping):
                if item.get("text") is not None:
                    pieces.append(str(item["text"]))
                elif item.get("content") is not None:
                    pieces.append(str(item["content"]))
        return "".join(pieces)
    return str(content)


def _json_safe(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, Mapping):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    return str(value)


def _response_metadata(response: Any) -> dict[str, Any]:
    response_metadata = getattr(response, "response_metadata", {})
    usage_metadata = getattr(response, "usage_metadata", {})
    response_metadata = response_metadata if isinstance(response_metadata, Mapping) else {}
    usage_metadata = usage_metadata if isinstance(usage_metadata, Mapping) else {}
    token_usage = response_metadata.get("token_usage") or response_metadata.get("usage")
    if not isinstance(token_usage, Mapping):
        token_usage = {}
    finish_reason = (
        response_metadata.get("finish_reason")
        or response_metadata.get("finishReason")
        or response_metadata.get("stop_reason")
    )
    response_id = getattr(response, "id", None)
    return {
        "finish_reason": _json_safe(finish_reason),
        "token_usage": _json_safe(token_usage),
        "usage_metadata": _json_safe(usage_metadata),
        "provider_response_id": _json_safe(response_id),
    }


def _load_tasks() -> tuple[dict[str, dict[str, Any]], str]:
    tasks = json.loads(QUALITY_DATASET.read_text(encoding="utf-8"))
    if not isinstance(tasks, list) or len(tasks) != 12:
        raise ValueError("Frozen quality dataset must contain exactly 12 tasks")
    task_map: dict[str, dict[str, Any]] = {}
    for task in tasks:
        task_id = str(task["task_id"])
        if task_id in task_map:
            raise ValueError(f"Duplicate frozen task: {task_id}")
        task_map[task_id] = task
    return task_map, _sha256(QUALITY_DATASET)


def _validate_original(rows: list[dict[str, Any]], tasks: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    if len(rows) != 24:
        raise ValueError(f"Original provider artifact must contain 24 rows, found {len(rows)}")
    seen_ids: set[str] = set()
    seen_pairs: set[tuple[str, str]] = set()
    for row in rows:
        task_id = str(row.get("sample_id", ""))
        configuration = str(row.get("configuration", ""))
        label = str(row.get("blind_label", ""))
        if task_id not in tasks or configuration not in {"BASELINE_NO_AGENTSHIELD", "FULL_AGENTSHIELD"}:
            raise ValueError("Original quality artifact contains an unexpected task/configuration")
        if label not in {"A", "B"} or (task_id, label) in seen_pairs:
            raise ValueError("Original quality artifact has duplicate or invalid blind labels")
        seen_pairs.add((task_id, label))
        record_id = str(row.get("request_id") or row.get("response_id") or "")
        if not record_id or record_id in seen_ids:
            raise ValueError("Original quality artifact has duplicate/missing record IDs")
        seen_ids.add(record_id)
        if row.get("provider") != PROVIDER or row.get("model") != MODEL or row.get("real_llm") is not True:
            raise ValueError("Original quality artifact is not uniformly Groq-backed")
        if row.get("fallback_excluded") is not True:
            raise ValueError("Original quality artifact contains a fallback-eligible row")
        expected = blinded_order(task_id, seed=SEED)
        expected_label = "A" if expected[0] == configuration else "B"
        if label != expected_label:
            raise ValueError(f"A/B mapping changed for {task_id}/{configuration}")
    if len({str(row["sample_id"]) for row in rows}) != 12 or seen_pairs != {
        (task_id, label) for task_id in tasks for label in ("A", "B")
    }:
        raise ValueError("Original quality artifact must contain exactly one A/B pair per task")
    return rows


def _invoke_once(service: ProviderService, prompt: str) -> tuple[str, float, dict[str, Any], dict[str, Any]]:
    import time

    started = time.perf_counter()
    try:
        response = service.invoke(prompt, max_tokens=REPAIRED_TOKEN_BUDGET)
    except ProviderInvocationError as exc:
        cause_name = exc.__cause__.__class__.__name__ if exc.__cause__ is not None else ""
        detail = f"{exc.reason}; cause={cause_name or 'unknown'}"
        raise RuntimeError(f"Provider call failed ({detail})") from exc
    latency = round((time.perf_counter() - started) * 1000.0, 3)
    metadata = service.metadata()
    response_info = _response_metadata(response)
    text = _message_text(response).strip()
    if metadata.get("provider") != PROVIDER or metadata.get("real_llm") is not True:
        raise RuntimeError(f"Provider verification failed: {metadata.get('provider')} real_llm={metadata.get('real_llm')}")
    if not text:
        raise RuntimeError(
            "Smoke/repair completion is empty; "
            f"finish_reason={response_info.get('finish_reason')!r} "
            f"token_usage={response_info.get('token_usage')!r}"
        )
    return text, latency, metadata, response_info


def _repaired_row(
    original: dict[str, Any],
    text: str,
    latency: float,
    metadata: dict[str, Any],
    response_info: dict[str, Any],
) -> dict[str, Any]:
    row = dict(original)
    row.update(
        {
            "response_text": text,
            "response_available": True,
            "provider_latency_ms": latency,
            "provider": metadata.get("provider"),
            "model": metadata.get("model"),
            "real_llm": bool(metadata.get("real_llm")),
            "regenerated": True,
            "regeneration_reason": REGENERATION_REASON,
            "repair_token_budget": REPAIRED_TOKEN_BUDGET,
            "repair_timestamp": _utc_now(),
            "original_record_id": original.get("request_id") or original.get("response_id"),
            "repair_response_id": response_info.get("provider_response_id") or f"repair-{uuid.uuid4().hex[:16]}",
            "repair_finish_reason": response_info.get("finish_reason"),
            "repair_token_usage": response_info.get("token_usage"),
            "repair_usage_metadata": response_info.get("usage_metadata"),
        }
    )
    return row


def _validate_repaired(rows: list[dict[str, Any]], tasks: dict[str, dict[str, Any]], dataset_sha256: str) -> None:
    if len(rows) != 24:
        raise ValueError("Repaired artifact must contain 24 rows")
    record_ids = [str(row.get("request_id") or row.get("response_id") or "") for row in rows]
    if not all(record_ids) or len(set(record_ids)) != 24:
        raise ValueError("Repaired artifact contains duplicate/missing original record IDs")
    pair_ids = {(str(row.get("sample_id")), str(row.get("blind_label"))) for row in rows}
    expected_pairs = {(task_id, label) for task_id in tasks for label in ("A", "B")}
    if pair_ids != expected_pairs:
        raise ValueError("Repaired artifact must contain exactly one A/B pair per task")
    for row in rows:
        if row.get("provider") != PROVIDER or row.get("model") != MODEL or row.get("real_llm") is not True:
            raise ValueError("Repaired artifact contains a non-Groq or non-real row")
        if row.get("fallback_excluded") is not True or not str(row.get("response_text") or "").strip():
            raise ValueError("Repaired artifact contains fallback or empty response text")
        if row.get("dataset_sha256") != dataset_sha256:
            raise ValueError("Repaired artifact does not match the frozen quality dataset")


def _load_checkpoint(original_rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    if not CHECKPOINT.exists():
        return {}
    checkpoint_rows = _read_jsonl(CHECKPOINT)
    original_by_id = {
        str(row.get("request_id") or row.get("response_id")): row for row in original_rows
    }
    result: dict[str, dict[str, Any]] = {}
    for row in checkpoint_rows:
        record_id = str(row.get("original_record_id") or "")
        if record_id not in original_by_id or row.get("regenerated") is not True:
            raise ValueError("Repair checkpoint contains an unexpected record")
        if record_id in result or not str(row.get("response_text") or "").strip():
            raise ValueError("Repair checkpoint contains duplicate or empty response text")
        result[record_id] = row
    return result


def _blind_rows(rows: list[dict[str, Any]], tasks: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    forbidden = ("BASELINE_NO_AGENTSHIELD", "FULL_AGENTSHIELD", "WITHOUT_AGENTSHIELD", "UNPROTECTED")
    for row in rows:
        task_id = str(row["sample_id"])
        packet_row = {
            "task_id": task_id,
            "task_prompt": str(tasks[task_id]["prompt"]),
            "blind_label": str(row["blind_label"]),
            "response_text": str(row["response_text"]),
        }
        serialized = json.dumps(packet_row, ensure_ascii=False).upper()
        if any(token in serialized for token in forbidden):
            raise ValueError("Repaired blind packet contains an unblinding token")
        result.append(packet_row)
    return result


def repair() -> dict[str, Any]:
    if REPAIRED_RAW.exists() or REPAIRED_BLIND.exists():
        raise ValueError("Repaired quality artifacts already exist; refusing to call the provider again")
    tasks, dataset_sha256 = _load_tasks()
    original_rows = _validate_original(_read_jsonl(ORIGINAL_RAW), tasks)
    _ = _read_jsonl(ORIGINAL_BLIND)
    missing = [row for row in original_rows if not str(row.get("response_text") or "").strip()]
    valid = [row for row in original_rows if str(row.get("response_text") or "").strip()]
    if len(valid) != 2 or len(missing) != 22:
        raise ValueError(f"Expected 2 valid and 22 missing rows, found {len(valid)} and {len(missing)}")
    print(f"Original rows: 24; valid preserved: {len(valid)}; missing: {len(missing)}")
    for row in missing:
        print(f"Missing: {row['sample_id']} configuration={row['configuration']} blind_label={row['blind_label']}")

    service = ProviderService(PROVIDER)
    checkpoint = _load_checkpoint(original_rows)
    repaired_by_id: dict[str, dict[str, Any]] = {
        str(row.get("request_id") or row.get("response_id")): dict(row) for row in valid
    }
    repaired_by_id.update(checkpoint)

    smoke = missing[0]
    smoke_id = str(smoke.get("request_id") or smoke.get("response_id"))
    if smoke_id in repaired_by_id:
        smoke_text = str(repaired_by_id[smoke_id]["response_text"])
        smoke_info = {
            "finish_reason": repaired_by_id[smoke_id].get("repair_finish_reason"),
            "token_usage": repaired_by_id[smoke_id].get("repair_token_usage"),
            "usage_metadata": repaired_by_id[smoke_id].get("repair_usage_metadata"),
        }
        print(f"Smoke PASS (checkpoint): {smoke['sample_id']} length={len(smoke_text)}")
    else:
        smoke_text, smoke_latency, smoke_metadata, smoke_info = _invoke_once(service, str(tasks[smoke["sample_id"]]["prompt"]))
        if len(smoke_text) < 20:
            raise RuntimeError(f"Smoke response was too short to answer the task (length={len(smoke_text)})")
        repaired_by_id[smoke_id] = _repaired_row(smoke, smoke_text, smoke_latency, smoke_metadata, smoke_info)
        _write_jsonl(CHECKPOINT, [row for row in repaired_by_id.values() if row.get("regenerated") is True])
        print(
            "Smoke PASS: "
            f"{smoke['sample_id']} configuration={smoke['configuration']} blind_label={smoke['blind_label']} "
            f"length={len(smoke_text)} finish_reason={smoke_info.get('finish_reason')!r} "
            f"provider={smoke_metadata.get('provider')} real_llm={smoke_metadata.get('real_llm')}"
        )

    for original in missing[1:]:
        record_id = str(original.get("request_id") or original.get("response_id"))
        if record_id in repaired_by_id:
            print(f"Repaired (checkpoint): {original['sample_id']} configuration={original['configuration']} blind_label={original['blind_label']}")
            continue
        text, latency, metadata, response_info = _invoke_once(service, str(tasks[original["sample_id"]]["prompt"]))
        repaired_by_id[record_id] = _repaired_row(original, text, latency, metadata, response_info)
        _write_jsonl(CHECKPOINT, [row for row in repaired_by_id.values() if row.get("regenerated") is True])
        print(
            "Repaired: "
            f"{original['sample_id']} configuration={original['configuration']} blind_label={original['blind_label']} "
            f"length={len(text)} finish_reason={response_info.get('finish_reason')!r}"
        )

    repaired_rows = [repaired_by_id[str(row.get("request_id") or row.get("response_id"))] for row in original_rows]
    _validate_repaired(repaired_rows, tasks, dataset_sha256)
    blind_rows = _blind_rows(repaired_rows, tasks)
    if len(blind_rows) != 24:
        raise ValueError("Repaired blind packet must contain 24 rows")
    _write_jsonl(REPAIRED_RAW, repaired_rows)
    _write_jsonl(REPAIRED_BLIND, blind_rows)
    CHECKPOINT.unlink(missing_ok=True)
    summary = {
        "schema_version": "phase16.5-quality-repair-v1",
        "status": "PENDING_HUMAN_EVALUATION",
        "provider": PROVIDER,
        "model": MODEL,
        "records": 24,
        "original_valid_records": 2,
        "regenerated_records": 22,
        "successful_repair_calls": 22,
        "additional_provider_calls": 22,
        "repair_token_budget": REPAIRED_TOKEN_BUDGET,
        "repair_token_budgets_used": {
            str(budget): sum(1 for row in repaired_rows if row.get("repair_token_budget") == budget)
            for budget in sorted({row.get("repair_token_budget") for row in repaired_rows if row.get("regenerated") is True})
        },
        "regeneration_reason": REGENERATION_REASON,
        "quality_dataset_sha256": dataset_sha256,
        "original_raw_artifact": str(ORIGINAL_RAW.relative_to(QUALITY_OUTPUT.parent.parent.parent)),
        "original_blind_artifact": str(ORIGINAL_BLIND.relative_to(QUALITY_OUTPUT.parent.parent.parent)),
        "repaired_raw_artifact": str(REPAIRED_RAW.relative_to(QUALITY_OUTPUT.parent.parent.parent)),
        "repaired_blind_artifact": str(REPAIRED_BLIND.relative_to(QUALITY_OUTPUT.parent.parent.parent)),
        "smoke_test": {
            "sample_id": smoke["sample_id"],
            "configuration": smoke["configuration"],
            "blind_label": smoke["blind_label"],
            "response_length": len(smoke_text),
            "finish_reason": smoke_info.get("finish_reason"),
            "token_usage": smoke_info.get("token_usage"),
            "usage_metadata": smoke_info.get("usage_metadata"),
        },
        "scored_records": 0,
        "fallback_excluded": True,
        "created_at": _utc_now(),
    }
    _write_json(REPAIRED_SUMMARY, summary)
    print("Validated: 24/24 non-empty responses; 12/12 complete pairs; provider=groq; real_llm=true; fallback=0")
    print(f"Repaired artifact: {REPAIRED_RAW}")
    print(f"Blind artifact: {REPAIRED_BLIND}")
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    try:
        repair()
    except (FileNotFoundError, ProviderInvocationError, ValueError, RuntimeError) as exc:
        raise SystemExit(f"QUALITY REPAIR FAILED: {exc}") from exc


if __name__ == "__main__":
    main()
