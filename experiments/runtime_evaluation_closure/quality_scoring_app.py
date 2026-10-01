"""Local blinded A/B quality-rating page.

This page intentionally reads only the repaired blind packet.  The
provider/configuration trace remains in the separate raw artifact and is not
loaded here, so the evaluator cannot accidentally unblind a response.
"""

from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import streamlit as st


ROOT = Path(__file__).resolve().parent
REPO_ROOT = ROOT.parent.parent
BLIND_PACKET = ROOT / "provider_verified_run" / "quality" / "quality_blind_scoring_repaired.jsonl"
QUALITY_DATASET = REPO_ROOT / "experiments" / "performance_quality" / "datasets" / "quality_tasks_v1.json"
RATINGS_PATH = ROOT / "provider_verified_run" / "quality" / "human_ratings.jsonl"
DIMENSIONS = ("task_success", "relevance", "completeness", "factuality", "helpfulness")
SCALE = (None, 1, 2, 3, 4, 5)


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        raise FileNotFoundError(f"Missing required artifact: {path}")
    rows: list[dict[str, Any]] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        value = json.loads(line)
        if not isinstance(value, dict):
            raise ValueError(f"Expected an object at {path}:{line_number}")
        rows.append(value)
    return rows


def _load_tasks() -> dict[str, str]:
    tasks = json.loads(QUALITY_DATASET.read_text(encoding="utf-8"))
    if not isinstance(tasks, list) or len(tasks) != 12:
        raise ValueError("The frozen quality dataset must contain exactly 12 tasks")
    result: dict[str, str] = {}
    for task in tasks:
        task_id = str(task["task_id"])
        result[task_id] = str(task["prompt"])
    return result


def _load_packet() -> tuple[list[str], dict[str, dict[str, dict[str, Any]]], dict[str, str]]:
    tasks = _load_tasks()
    grouped: dict[str, dict[str, dict[str, Any]]] = defaultdict(dict)
    for row in _read_jsonl(BLIND_PACKET):
        task_id = str(row.get("task_id", ""))
        label = str(row.get("blind_label", ""))
        if task_id not in tasks or label not in {"A", "B"}:
            raise ValueError("Blind packet contains an unexpected task or label")
        task_prompt = str(row.get("task_prompt", ""))
        if not task_prompt or task_prompt != tasks[task_id]:
            raise ValueError(f"Blind packet prompt mismatch for {task_id}")
        if "configuration" in row or "provider" in row or "model" in row:
            raise ValueError("Blind packet contains an unblinding field")
        serialized = json.dumps(row, ensure_ascii=False).upper()
        if any(token in serialized for token in ("BASELINE_NO_AGENTSHIELD", "FULL_AGENTSHIELD", "WITHOUT_AGENTSHIELD", "UNPROTECTED")):
            raise ValueError("Blind packet contains an unblinding token")
        if not str(row.get("response_text") or "").strip():
            raise ValueError(f"Blind packet response integrity failure for {task_id}/{label}; scoring disabled")
        if label in grouped[task_id]:
            raise ValueError(f"Duplicate blind response for {task_id}/{label}")
        grouped[task_id][label] = row
    task_ids = list(tasks)
    if len(grouped) != len(task_ids) or any(set(grouped[task_id]) != {"A", "B"} for task_id in task_ids):
        raise ValueError("Blind packet must contain exactly one A/B pair for each task")
    if sum(len(grouped[task_id]) for task_id in task_ids) != 24:
        raise ValueError("Blind packet must contain exactly 24 response records")
    return task_ids, grouped, tasks


def _load_ratings() -> dict[tuple[str, str], dict[str, Any]]:
    if not RATINGS_PATH.exists():
        return {}
    result: dict[tuple[str, str], dict[str, Any]] = {}
    for row in _read_jsonl(RATINGS_PATH):
        task_id = str(row.get("sample_id", ""))
        label = str(row.get("blind_label", ""))
        if label not in {"A", "B"} or any(row.get(d) not in {1, 2, 3, 4, 5} for d in DIMENSIONS):
            continue
        result[(task_id, label)] = row
    return result


def _save_ratings(ratings: dict[tuple[str, str], dict[str, Any]]) -> None:
    RATINGS_PATH.parent.mkdir(parents=True, exist_ok=True)
    content = "".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for _, row in sorted(ratings.items()))
    temporary = RATINGS_PATH.with_suffix(".tmp")
    temporary.write_text(content, encoding="utf-8", newline="\n")
    temporary.replace(RATINGS_PATH)


def _score_widget(task_id: str, label: str, dimension: str, existing: Any) -> int | None:
    options: list[int | None] = list(SCALE)
    index = options.index(existing) if existing in options else 0
    return st.selectbox(
        dimension.replace("_", " ").title(),
        options,
        index=index,
        format_func=lambda value: "Select a score…" if value is None else str(value),
        key=f"score_{task_id}_{label}_{dimension}",
    )


def main() -> None:
    st.set_page_config(page_title="Human Quality Scoring", layout="wide")
    st.title("Human Quality Scoring")
    st.caption("Blinded A/B evaluation — score the responses, not the system.")
    try:
        task_ids, grouped, prompts = _load_packet()
        ratings = _load_ratings()
    except (FileNotFoundError, ValueError, json.JSONDecodeError) as exc:
        st.error(str(exc))
        st.stop()

    completed = sum(all((task_id, label) in ratings for label in ("A", "B")) for task_id in task_ids)
    st.progress(completed / len(task_ids), text=f"Progress: {completed}/{len(task_ids)} task pairs scored")
    if completed == len(task_ids):
        st.success("All task pairs are scored. You may stop the app; analysis can now be run separately.")

    if "task_index" not in st.session_state:
        st.session_state.task_index = 0
    selected = st.selectbox(
        "Task pair",
        range(len(task_ids)),
        index=int(st.session_state.task_index),
        format_func=lambda index: f"Task {index + 1} — {task_ids[index]}",
    )
    st.session_state.task_index = selected
    task_id = task_ids[selected]
    st.subheader(f"Task {selected + 1}")
    st.text_area("Task prompt", value=prompts[task_id], height=100, disabled=True)
    st.info("Use the same anchors for every response: 1 very poor/failed · 2 poor · 3 acceptable · 4 good · 5 excellent.")

    with st.form(f"rating_form_{task_id}"):
        columns = st.columns(2)
        pending: dict[str, dict[str, Any]] = {}
        for column, label in zip(columns, ("A", "B")):
            with column:
                st.markdown(f"### Response {label}")
                response = str(grouped[task_id][label].get("response_text") or "").strip()
                st.text_area(
                    f"Response {label} text",
                    value=response,
                    height=240,
                    disabled=True,
                    key=f"response_{task_id}_{label}",
                )
                existing = ratings.get((task_id, label), {})
                scores = {dimension: _score_widget(task_id, label, dimension, existing.get(dimension)) for dimension in DIMENSIONS}
                notes = st.text_area("Optional notes", value=str(existing.get("notes") or ""), key=f"notes_{task_id}_{label}", height=90)
                pending[label] = {**scores, "notes": notes}

        save_next = st.form_submit_button("Save ratings and go to next task")
        save_only = st.form_submit_button("Save ratings")
        if save_next or save_only:
            missing = [(label, dimension) for label, values in pending.items() for dimension in DIMENSIONS if values[dimension] is None]
            if missing:
                st.error("Please select a 1–5 score for every dimension of both responses before saving.")
            else:
                timestamp = datetime.now(timezone.utc).isoformat()
                for label, values in pending.items():
                    ratings[(task_id, label)] = {
                        "sample_id": task_id,
                        "blind_label": label,
                        **{dimension: int(values[dimension]) for dimension in DIMENSIONS},
                        "notes": str(values["notes"]),
                        "rated_at": timestamp,
                        "rubric_scale": "1=very poor/failed; 2=poor; 3=acceptable; 4=good; 5=excellent",
                        "evaluator_version": "phase16.5-human-rating-v1",
                    }
                _save_ratings(ratings)
                st.success("Ratings saved.")
                if save_next:
                    st.session_state.task_index = (selected + 1) % len(task_ids)
                    st.rerun()


if __name__ == "__main__":
    main()
