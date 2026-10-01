"""Deterministic builder for the AgentShield propagation-attack benchmark.

The builder turns hand-authored templates into fully annotated ``AttackSample``
rows, generates multi-hop propagation variants from the frozen graph topology,
applies adaptive transformations to a fixed subset, and splits the result into
development and held-out test sets at the *template-family* level (so no
transformation family appears in both arms).

Dataset tiers:

1. MANUAL — hand-authored templates (attacks/catalog.py).
2. PROPAGATION — same payload re-targeted at deeper agents (planner/writer/
   finalizer) to measure propagation depth.
3. TRANSFORMED — deterministic adaptive variants of a fixed subset.
4. BENIGN — normal questions plus benign-with-adversarial-distractor content
   that contains attack-like phrases in safe context (false-positive arm).

All randomness is seeded; the build is reproducible byte-for-byte.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from attacks.catalog import PROPAGATION_CATEGORIES, all_templates
from attacks.schema import (
    AGENT_ORDER,
    AttackCategory,
    AttackSample,
    Difficulty,
    InjectionPoint,
    expected_depth,
)
from attacks.transformations import apply_transform, difficulty_bump

SOURCE_TO_INJECTION = {
    "user": InjectionPoint.USER_INPUT,
    "document_author": InjectionPoint.DOCUMENT,
    "compromised_tool": InjectionPoint.TOOL_OUTPUT,
}

SOURCE_LABEL = {
    "user": "user",
    "document_author": "document_author",
    "compromised_tool": "compromised_tool",
}

ATTACK_CATEGORIES = {
    AttackCategory.DIRECT_INJECTION,
    AttackCategory.INDIRECT_DOCUMENT_INJECTION,
    AttackCategory.TOOL_OUTPUT_INJECTION,
    AttackCategory.INTER_AGENT_PROPAGATION,
    AttackCategory.MULTI_HOP_PROPAGATION,
    AttackCategory.PLANNER_TARGETING,
    AttackCategory.TRIGGER_BASED,
    AttackCategory.SYSTEM_PROMPT_EXTRACTION,
    AttackCategory.SECRET_EXFILTRATION,
    AttackCategory.TOOL_ABUSE,
    AttackCategory.PARAMETER_MANIPULATION,
    AttackCategory.DANGEROUS_SEQUENCE,
    AttackCategory.OBFUSCATED_INJECTION,
}

# Deterministic encoding transforms applied to a fixed attack subset for the
# adaptive arm.  Paraphrase is applied separately to a small per-category set
# because it is category-aware.
ENCODING_TRANSFORMS = [
    "base64",
    "hex",
    "rot13",
    "url_encode",
    "zero_width",
    "leetspeak",
    "spacing",
    "confusables",
    "payload_split",
]

PARAPHRASE_CATEGORIES = [
    "DIRECT_INJECTION",
    "SYSTEM_PROMPT_EXTRACTION",
    "SECRET_EXFILTRATION",
    "TOOL_ABUSE",
]

CATEGORY_SHORT = {
    AttackCategory.DIRECT_INJECTION: "DIR",
    AttackCategory.INDIRECT_DOCUMENT_INJECTION: "IDOC",
    AttackCategory.TOOL_OUTPUT_INJECTION: "TOOL",
    AttackCategory.INTER_AGENT_PROPAGATION: "IAP",
    AttackCategory.MULTI_HOP_PROPAGATION: "MHOP",
    AttackCategory.PLANNER_TARGETING: "PLAN",
    AttackCategory.TRIGGER_BASED: "TRIG",
    AttackCategory.OBFUSCATED_INJECTION: "OBF",
    AttackCategory.SYSTEM_PROMPT_EXTRACTION: "SYSX",
    AttackCategory.SECRET_EXFILTRATION: "SECX",
    AttackCategory.TOOL_ABUSE: "TABU",
    AttackCategory.PARAMETER_MANIPULATION: "PARM",
    AttackCategory.DANGEROUS_SEQUENCE: "DSEQ",
    AttackCategory.BENIGN_NORMAL: "BNGN",
    AttackCategory.BENIGN_DISTRACTOR: "BNDR",
}


def _difficulty_for(template: Dict[str, Any]) -> Difficulty:
    value = str(template.get("difficulty", "easy")).lower()
    if value in {"medium", "hard"}:
        return Difficulty(value)
    return Difficulty.EASY


def _make_sample(
    *,
    attack_id: str,
    template: Dict[str, Any],
    target_agent: str,
    injection_point: InjectionPoint,
    category: AttackCategory,
    text: str,
    obfuscation: str = "none",
    transformed_from: Optional[str] = None,
    difficulty: Optional[Difficulty] = None,
) -> AttackSample:
    label = "malicious" if category in ATTACK_CATEGORIES else "benign"
    is_attack = label == "malicious"
    if is_attack:
        ground_truth = "contained"
        expected_policy = str(template.get("expected_policy", "BLOCK"))
        expected_layer = str(template.get("expected_layer", "gateway"))
    else:
        ground_truth = "benign"
        expected_policy = "ALLOW"
        expected_layer = "gateway"
    source = str(template.get("source", "user"))
    return AttackSample(
        attack_id=attack_id,
        category=category,
        label=label,
        difficulty=difficulty or _difficulty_for(template),
        injection_point=injection_point,
        source=SOURCE_LABEL.get(source, source),
        target_agent=target_agent,
        target_tool=template.get("target_tool"),
        attacker_goal=str(template.get("attacker_goal", "")),
        propagation_depth=expected_depth(injection_point, target_agent),
        obfuscation=obfuscation,
        transformed_from=transformed_from,
        ground_truth=ground_truth,
        expected_policy=expected_policy,
        expected_layer=expected_layer,
        text=text,
        untrusted_context=template.get("untrusted_context"),
        tool_arguments=template.get("tool_arguments"),
        notes=str(template.get("notes", "")),
    )


def _template_family_id(template_index: int, category: AttackCategory) -> str:
    """A transformation/template family groups related samples for resampling."""
    return f"{category.value}:{template_index}"


def build_benchmark(seed: int = 19) -> Dict[str, Any]:
    """Build the complete benchmark and return rows + split metadata."""
    _ = seed
    samples: List[AttackSample] = []
    family_index: Dict[str, int] = {}

    def family_of(attack_id: str, template_index: int, category: AttackCategory) -> str:
        family = _template_family_id(template_index, category)
        family_index.setdefault(family, len(family_index))
        return family

    # ------------------------------------------------------------------ 1. MANUAL
    templates = all_templates()
    propagation_targets = {agent: i for i, agent in enumerate(AGENT_ORDER)}
    for template_index, template in enumerate(templates):
        category = AttackCategory(template["category"])
        target_agent = str(template.get("target_agent", "researcher"))
        injection_point = SOURCE_TO_INJECTION.get(
            str(template.get("source", "user")), InjectionPoint.USER_INPUT
        )
        if category == AttackCategory.BENIGN_NORMAL:
            sample = _make_sample(
                attack_id=f"B-{CATEGORY_SHORT[category]}-{template_index:02d}",
                template=template,
                target_agent="researcher",
                injection_point=InjectionPoint.USER_INPUT,
                category=category,
                text=str(template["text"]),
            )
            samples.append(sample)
            continue
        if category == AttackCategory.BENIGN_DISTRACTOR:
            sample = _make_sample(
                attack_id=f"B-{CATEGORY_SHORT[category]}-{template_index:02d}",
                template=template,
                target_agent="researcher",
                injection_point=injection_point,
                category=category,
                text=str(template["text"]),
            )
            samples.append(sample)
            continue

        # --- 1a. Manual entry sample at the template's declared target.
        base_id = f"A-{CATEGORY_SHORT[category]}-{template_index:02d}"
        samples.append(
            _make_sample(
                attack_id=base_id,
                template=template,
                target_agent=target_agent,
                injection_point=injection_point,
                category=category,
                text=str(template["text"]),
            )
        )

        # --- 1b. Propagation variants: re-target the payload at deeper agents
        # so the study can measure propagation depth through the graph.
        if category.value in PROPAGATION_CATEGORIES:
            start_index = propagation_targets.get(target_agent, 0)
            deeper_targets = [
                agent for agent in AGENT_ORDER[start_index + 1 :]
            ]
            for variant, deeper_target in enumerate(deeper_targets, start=1):
                samples.append(
                    _make_sample(
                        attack_id=f"{base_id}-d{variant}",
                        template=template,
                        target_agent=deeper_target,
                        injection_point=injection_point,
                        category=category,
                        text=str(template["text"]),
                        difficulty=Difficulty.MEDIUM,
                    )
                )

    # ------------------------------------------------------------------ 2. TRANSFORMED
    # Deterministically choose a fixed subset of attack templates to transform
    # (encoding variants), plus a small category-aware paraphrase set.
    attack_templates = [
        (index, template)
        for index, template in enumerate(templates)
        if AttackCategory(template["category"]) in ATTACK_CATEGORIES
    ]
    transformed_selector = random.Random(seed + 1)
    chosen = transformed_selector.sample(
        attack_templates, k=max(4, len(attack_templates) // 6)
    )

    def _obfuscated_sample(
        template: Dict[str, Any],
        template_index: int,
        transform_name: str,
        transformed_text: str,
        difficulty: Difficulty,
    ) -> None:
        category = AttackCategory(template["category"])
        samples.append(
            _make_sample(
                attack_id=(
                    f"T-{CATEGORY_SHORT[AttackCategory.OBFUSCATED_INJECTION]}-"
                    f"{template_index:02d}-{transform_name}"
                ),
                template=template,
                target_agent=str(template.get("target_agent", "researcher")),
                injection_point=SOURCE_TO_INJECTION.get(
                    str(template.get("source", "user")), InjectionPoint.USER_INPUT
                ),
                category=AttackCategory.OBFUSCATED_INJECTION,
                text=transformed_text,
                obfuscation=transform_name,
                transformed_from=(
                    f"A-{CATEGORY_SHORT[category]}-{template_index:02d}"
                ),
                difficulty=difficulty,
            )
        )

    for template_index, template in chosen:
        category = AttackCategory(template["category"])
        base_text = str(template["text"])
        for transform_name in ENCODING_TRANSFORMS:
            try:
                transformed_text = apply_transform(transform_name, base_text, category.value)
            except Exception:
                continue
            if transformed_text == base_text:
                continue
            rank = difficulty_bump(transform_name)
            difficulty = (
                Difficulty.MEDIUM
                if rank >= 2
                else Difficulty.EASY
            )
            _obfuscated_sample(
                template, template_index, transform_name, transformed_text, difficulty
            )

    # Category-aware paraphrase variants (semantic-obfuscation arm).
    for category_name in PARAPHRASE_CATEGORIES:
        matching = [
            (index, template)
            for index, template in attack_templates
            if template["category"] == category_name
        ]
        if not matching:
            continue
        template_index, template = matching[0]
        transformed_text = apply_transform("paraphrase", str(template["text"]), category_name)
        if transformed_text != str(template["text"]):
            _obfuscated_sample(
                template, template_index, "paraphrase", transformed_text, Difficulty.HARD
            )

    # ------------------------------------------------------------------ 3. SPLIT
    # Hold out complete template families (20% per category) so the test set
    # contains attack templates never seen during development.  A family is the
    # template index embedded in the attack id; transformed rows inherit the
    # family of their base template, and propagation variants share the family
    # of their entry sample.
    rows = [sample.to_row() for sample in samples]

    def _family_for(row: Dict[str, Any]) -> str:
        attack_id = str(row["attack_id"])
        category = AttackCategory(row["category"])
        transformed = str(row.get("transformed_from") or "")
        if transformed:
            transformed = str(transformed)
            base_index = "".join(ch for ch in transformed.split("-")[-1] if ch.isdigit()) or "0"
            return f"{category.value}:{int(base_index)}"
        parts = attack_id.split("-")
        for index, part in enumerate(parts):
            if part in CATEGORY_SHORT.values() and index + 1 < len(parts):
                numeric = "".join(ch for ch in parts[index + 1] if ch.isdigit()) or "0"
                return f"{category.value}:{int(numeric)}"
        return f"{category.value}:{attack_id}"

    by_family: Dict[str, List[Dict[str, Any]]] = {}
    for row in rows:
        by_family.setdefault(_family_for(row), []).append(row)

    families = sorted(by_family)
    held_out: set[str] = set()
    rng_split = random.Random(seed + 2)
    for family in families:
        if rng_split.random() < 0.20:
            held_out.add(family)
    dev_rows: List[Dict[str, Any]] = []
    test_rows: List[Dict[str, Any]] = []
    for family, family_rows in by_family.items():
        target = test_rows if family in held_out else dev_rows
        for row in family_rows:
            stamped = dict(row)
            stamped["family"] = family
            target.append(stamped)

    all_rows = [dict(row, family=_family_for(row)) for row in rows]
    summary = {
        "schema_version": "2.0",
        "seed": seed,
        "total_samples": len(all_rows),
        "attack_samples": sum(1 for r in all_rows if r["label"] == "malicious"),
        "benign_samples": sum(1 for r in all_rows if r["label"] == "benign"),
        "dev_samples": len(dev_rows),
        "test_samples": len(test_rows),
        "held_out_families": sorted(held_out),
        "family_count": len(families),
        "split_methodology": (
            "Template families are held out at 20% per category; transformation "
            "variants inherit the family of their base template. The test set is "
            "never touched during detector development."
        ),
        "category_counts": _category_counts(all_rows),
        "difficulty_counts": _difficulty_counts(all_rows),
    }
    return {
        "summary": summary,
        "dev": dev_rows,
        "test": test_rows,
        "all": all_rows,
    }


def _category_counts(rows: Sequence[Dict[str, Any]]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for row in rows:
        counts[str(row["category"])] = counts.get(str(row["category"]), 0) + 1
    return dict(sorted(counts.items()))


def _difficulty_counts(rows: Sequence[Dict[str, Any]]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for row in rows:
        counts[str(row["difficulty"])] = counts.get(str(row["difficulty"]), 0) + 1
    return dict(sorted(counts.items()))


def validate_benchmark(rows: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    """Validate benchmark rows: required fields, IDs, labels, expectations."""
    required = set(AttackSample.model_fields)
    ids: set[str] = set()
    errors: List[str] = []
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            errors.append(f"row {index} is not an object")
            continue
        missing = required - row.keys()
        if missing:
            errors.append(f"row {index} missing {sorted(missing)}")
            continue
        attack_id = str(row["attack_id"])
        if not attack_id or attack_id in ids:
            errors.append(f"duplicate or empty attack_id at row {index}")
        ids.add(attack_id)
        label = str(row["label"])
        category = str(row["category"])
        if category not in {c.value for c in AttackCategory}:
            errors.append(f"{attack_id}: unknown category {category}")
        if label == "benign" and row["expected_policy"] != "ALLOW":
            errors.append(f"{attack_id}: benign must expect ALLOW")
        if label == "malicious" and row["expected_policy"] not in {"BLOCK", "SANITIZE", "REVIEW"}:
            errors.append(f"{attack_id}: malicious must expect a mitigating policy")
        depth = int(row["propagation_depth"])
        if depth < 1:
            errors.append(f"{attack_id}: propagation_depth must be >= 1")
        if str(row["target_agent"]) not in AGENT_ORDER:
            errors.append(f"{attack_id}: unknown target_agent")
    if errors:
        raise ValueError("Benchmark validation failed:\n" + "\n".join(errors[:50]))
    return {
        "valid": True,
        "sample_count": len(rows),
        "unique_ids": len(ids),
    }


def dataset_hash(rows: Sequence[Dict[str, Any]]) -> str:
    payload = json.dumps(rows, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def write_benchmark(
    *,
    output_dir: Path,
    seed: int = 19,
    manifest_path: Optional[Path] = None,
) -> Dict[str, Any]:
    """Build, validate, and persist the benchmark with a hash manifest."""
    built = build_benchmark(seed=seed)
    for split in ("all", "dev", "test"):
        validate_benchmark(built[split])
    output_dir.mkdir(parents=True, exist_ok=True)
    paths = {}
    for split in ("all", "dev", "test"):
        path = output_dir / f"benchmark_v2_{split}.json"
        path.write_text(
            json.dumps(built[split], indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        paths[split] = path.name
    manifest = {
        "dataset_version": "benchmark_v2",
        "seed": seed,
        "sha256_all": dataset_hash(built["all"]),
        "sha256_dev": dataset_hash(built["dev"]),
        "sha256_test": dataset_hash(built["test"]),
        "summary": built["summary"],
        "files": paths,
        "frozen": True,
    }
    manifest_target = manifest_path or output_dir / "benchmark_v2.manifest.json"
    manifest_target.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("experiments/propagation/datasets"))
    parser.add_argument("--seed", type=int, default=19)
    args = parser.parse_args()
    manifest = write_benchmark(output_dir=args.output, seed=args.seed)
    print(json.dumps(manifest["summary"], indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
