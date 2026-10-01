"""Explicit provider inventory and safe runtime validation.

This command is opt-in because cloud validation performs one small completion.
It never prints keys or raw provider exceptions.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from providers.service import (  # noqa: E402
    SUPPORTED_PROVIDERS,
    get_provider_status,
    validate_provider,
)


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate configured AgentShield LLM providers")
    parser.add_argument("--provider", choices=SUPPORTED_PROVIDERS, help="Validate only one provider")
    parser.add_argument("--json", action="store_true", dest="as_json", help="Emit machine-readable output")
    args = parser.parse_args()

    if args.provider:
        snapshot = validate_provider(args.provider)
        result = {args.provider: snapshot.as_dict()}
    else:
        result = get_provider_status(probe=True)["providers"]
    payload = {"providers": result}
    if args.as_json:
        print(json.dumps(payload, sort_keys=True))
    else:
        print("AgentShield provider validation (safe metadata only)")
        for name, details in result.items():
            print(
                f"- {name}: status={details.get('status')} "
                f"model={details.get('model', '<none>')} "
                f"runtime_verified={details.get('runtime_verified', False)}"
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
