"""Compute processed metrics from raw Phase 15 JSONL results."""

from __future__ import annotations

import argparse
import json

from .config import CONFIG_NAMES, ROOT, load_config
from .metrics import calculate_metrics, uncertainty
from .run_evaluation import _assert_frozen, PROCESSED_DIR, RAW_DIR


def compute_config(name: str, *, bootstrap_replicates: int = 1000) -> dict:
    path = RAW_DIR / f"{load_config(name).name}.jsonl"
    if not path.exists():
        raise FileNotFoundError(f"Raw results not found: {path}")
    records = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    result = {
        "configuration": load_config(name).as_dict(),
        "raw_results": str(path.relative_to(ROOT.parent.parent)),
        "metrics": calculate_metrics(records),
        "grouped_bootstrap_95_ci": uncertainty(records, replicates=bootstrap_replicates),
    }
    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    (PROCESSED_DIR / f"{load_config(name).name}.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", choices=CONFIG_NAMES)
    parser.add_argument("--all", action="store_true")
    parser.add_argument("--bootstrap-replicates", type=int, default=1000)
    args = parser.parse_args()
    if args.config and args.all:
        parser.error("choose --config or --all")
    _assert_frozen()
    names = CONFIG_NAMES if args.all else [args.config or "full"]
    print(json.dumps({name: compute_config(name, bootstrap_replicates=args.bootstrap_replicates) for name in names}, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
