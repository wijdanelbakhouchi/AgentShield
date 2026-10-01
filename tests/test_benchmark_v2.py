"""Tests for the propagation-attack benchmark builder and validation."""

from __future__ import annotations

import pytest

from attacks.benchmark import build_benchmark, dataset_hash, validate_benchmark, write_benchmark
from attacks.schema import AGENT_ORDER, expected_depth


@pytest.fixture(scope="module")
def built():
    return build_benchmark(seed=19)


def test_build_is_valid_and_balanced(built):
    for split in ("all", "dev", "test"):
        validate_benchmark(built[split])
    summary = built["summary"]
    assert summary["total_samples"] == len(built["all"])
    assert summary["attack_samples"] + summary["benign_samples"] == summary["total_samples"]
    assert summary["attack_samples"] > 0
    assert summary["benign_samples"] >= 16
    assert summary["dev_samples"] + summary["test_samples"] == summary["total_samples"]


def test_held_out_test_set_has_attacks_and_benign(built):
    test_rows = built["test"]
    assert any(r["label"] == "malicious" for r in test_rows)
    assert any(r["label"] == "benign" for r in test_rows)


def test_metadata_consistency(built):
    for row in built["all"]:
        assert row["target_agent"] in AGENT_ORDER
        assert int(row["propagation_depth"]) >= 1
        if row["label"] == "malicious":
            assert row["expected_policy"] in {"BLOCK", "SANITIZE", "REVIEW"}
        else:
            assert row["expected_policy"] == "ALLOW"


def test_transformed_rows_inherit_family(built):
    transformed = [r for r in built["all"] if r.get("transformed_from")]
    assert transformed
    test_families = {r["family"] for r in built["test"]}
    for row in transformed:
        if row["family"] in test_families:
            assert row["obfuscation"] != "none"


def test_obfuscation_arms_present(built):
    obfuscations = {r["obfuscation"] for r in built["all"] if r["category"] == "OBFUSCATED_INJECTION"}
    assert {"base64", "rot13", "paraphrase"} <= obfuscations


def test_deterministic_build():
    first = build_benchmark(seed=19)
    second = build_benchmark(seed=19)
    assert dataset_hash(first["all"]) == dataset_hash(second["all"])


def test_depth_matches_expected_depth(built):
    for row in built["all"]:
        expected = expected_depth(row["injection_point"], row["target_agent"])
        assert int(row["propagation_depth"]) == expected


def test_write_benchmark_roundtrip(tmp_path):
    manifest = write_benchmark(output_dir=tmp_path, seed=19)
    assert manifest["frozen"] is True
    assert (tmp_path / "benchmark_v2_all.json").exists()
    assert (tmp_path / "benchmark_v2.manifest.json").exists()