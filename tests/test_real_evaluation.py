from pathlib import Path

from evaluation.real_evaluation import run_security_evaluation, run_workflow_security_evaluation


def test_real_evaluation_has_no_false_negatives() -> None:
    report = run_security_evaluation(Path("real_benchmark.json"))
    assert report["confusion_matrix"]["fn"] == 0


def test_workflow_mitigates_attacks_before_final_answer() -> None:
    report = run_workflow_security_evaluation(Path("real_benchmark.json"))
    assert report["workflow_mitigation_rate"] == 1.0
