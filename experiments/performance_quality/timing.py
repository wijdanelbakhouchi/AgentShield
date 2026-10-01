"""Pure latency statistics used by the Phase 16 processing pipeline."""

from __future__ import annotations

import math
import statistics
from typing import Iterable, Sequence


def percentile(values: Iterable[float], probability: float) -> float | None:
    """Return a linearly interpolated percentile, or ``None`` for no data."""

    numbers = sorted(float(value) for value in values)
    if not numbers:
        return None
    if not 0.0 <= probability <= 1.0:
        raise ValueError("probability must be between 0 and 1")
    position = (len(numbers) - 1) * probability
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return round(numbers[lower], 3)
    fraction = position - lower
    return round(numbers[lower] + (numbers[upper] - numbers[lower]) * fraction, 3)


def summarize(values: Sequence[float] | Iterable[float]) -> dict[str, float | int | None]:
    numbers = [float(value) for value in values]
    if not numbers:
        return {"count": 0, **{key: None for key in ("mean", "median", "min", "max", "p50", "p95", "p99", "std")}}
    return {
        "count": len(numbers),
        "mean": round(statistics.fmean(numbers), 3),
        "median": round(statistics.median(numbers), 3),
        "min": round(min(numbers), 3),
        "max": round(max(numbers), 3),
        "p50": percentile(numbers, 0.50),
        "p95": percentile(numbers, 0.95),
        "p99": percentile(numbers, 0.99),
        "std": round(statistics.stdev(numbers), 3) if len(numbers) > 1 else 0.0,
    }


def paired_overhead(baseline: Sequence[dict], protected: Sequence[dict]) -> dict:
    """Summarize protected-minus-baseline totals matched by sample/run number."""

    baseline_map = {(row["sample_id"], int(row["run_number"])): row for row in baseline}
    deltas: list[float] = []
    for row in protected:
        key = (row["sample_id"], int(row["run_number"]))
        reference = baseline_map.get(key)
        if reference is not None:
            deltas.append(float(row["total_ms"]) - float(reference["total_ms"]))
    result = summarize(deltas)
    baseline_values = [float(row["total_ms"]) for row in baseline]
    protected_values = [float(row["total_ms"]) for row in protected]
    baseline_mean = statistics.fmean(baseline_values) if baseline_values else None
    protected_mean = statistics.fmean(protected_values) if protected_values else None
    result["absolute_overhead_ms"] = round(protected_mean - baseline_mean, 3) if baseline_mean is not None and protected_mean is not None else None
    result["relative_overhead_percent"] = round((protected_mean - baseline_mean) / baseline_mean * 100.0, 3) if baseline_mean not in (None, 0) and protected_mean is not None else None
    return result
