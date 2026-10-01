"""Inventory source and scan tracked/current history without emitting secrets."""
import ast
import hashlib
import json
from pathlib import Path
import re
import subprocess


def main():
    root = Path(__file__).resolve().parents[1]
    excluded = {".git", ".venv", "node_modules", "__pycache__", "artifacts", "dist", ".venv-audit"}
    inventory = []
    for path in root.rglob("*.py"):
        if set(path.relative_to(root).parts) & excluded:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8-sig"))
        inventory.append({"path": path.relative_to(root).as_posix(), "lines": len(path.read_text(encoding="utf-8-sig").splitlines()),
                          "definitions": [n.name for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))]})
    pattern = re.compile(r"(?:sk-[A-Za-z0-9_-]{20,}|gsk_[A-Za-z0-9_-]{20,}|AIzaSy[A-Za-z0-9_-]{33}|AKIA[0-9A-Z]{16}|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----)")
    findings = []
    def scan(text, location):
        for match in pattern.finditer(text):
            token = match.group()
            if len(set(token)) < 12 or any(s in token.lower() for s in ("example", "placeholder", "abcdefghijklmnopqrstuvwxyz", "test", "dummy", "fake")):
                continue
            findings.append({"location": location, "fingerprint": hashlib.sha256(token.encode()).hexdigest()[:12]})
    tracked = subprocess.run(["git", "ls-files"], cwd=root, capture_output=True, text=True, check=True).stdout.splitlines()
    for name in tracked:
        path = root / name
        if path.is_file() and path.stat().st_size < 10_000_000:
            scan(path.read_text(encoding="utf-8", errors="ignore"), name)
    history = subprocess.run(["git", "log", "--all", "--format=COMMIT %H", "-p", "--no-ext-diff"], cwd=root, capture_output=True, text=True, encoding="utf-8", errors="replace", check=True).stdout
    commit, path = "", ""
    for line in history.splitlines():
        if line.startswith("COMMIT "):
            commit = line[7:]
        elif line.startswith("+++ b/"):
            path = line[6:]
        elif line.startswith(("+", "-")):
            scan(line, f"history:{commit}:{path}")
    output = root / "artifacts/audit-2026-09-14"
    output.mkdir(parents=True, exist_ok=True)
    (output / "inventory.json").write_text(json.dumps(inventory, indent=2), encoding="utf-8")
    (output / "secrets-scan.json").write_text(json.dumps({"tracked_files": len(tracked), "history_scanned": True, "candidates": findings, "scope": "provider-key formats and private-key headers; heuristic, not exhaustive"}, indent=2), encoding="utf-8")
    print(json.dumps({"python_files": len(inventory), "tracked_files": len(tracked), "secret_candidates": len(findings)}))


if __name__ == "__main__":
    main()
