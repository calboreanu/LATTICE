"""Tests for LATTICE training-data infrastructure (KAN-295)."""
from __future__ import annotations

from lattice.training_data import (
    LatticeTrainingCategory,
    LatticeTrainingDataset,
    build_training_example,
    escalation_packaging_example,
    rejection_replan_example,
    translation_example,
)


def _example(example_id: str, category: LatticeTrainingCategory):
    return build_training_example(
        example_id=example_id,
        category=category,
        prompt_input={"in": example_id},
        expected_output={"out": category.value},
    )


def test_dataset_add_deduplicates_examples() -> None:
    dataset = LatticeTrainingDataset()
    one = _example("ex-1", LatticeTrainingCategory.MANDATE_TO_BUNDLE)
    added = dataset.add([one, one])

    assert added == 1
    assert len(dataset.examples) == 1


def test_export_and_load_jsonl_round_trip(tmp_path) -> None:
    dataset = LatticeTrainingDataset()
    dataset.add(
        [
            _example("ex-1", LatticeTrainingCategory.MANDATE_TO_BUNDLE),
            _example("ex-2", LatticeTrainingCategory.REJECTION_REPLAN),
        ]
    )
    path = tmp_path / "lattice_training.jsonl"
    written = dataset.export_jsonl(path)
    loaded = LatticeTrainingDataset.load_jsonl(path)

    assert written == 2
    assert len(loaded.examples) == 2
    assert loaded.category_counts()["MANDATE_TO_BUNDLE"] == 1
    assert loaded.category_counts()["REJECTION_REPLAN"] == 1


def test_split_is_deterministic_and_conserves_examples() -> None:
    dataset = LatticeTrainingDataset()
    dataset.add(
        _example(f"ex-{idx}", LatticeTrainingCategory.CONFIDENCE_CALIBRATION)
        for idx in range(10)
    )

    a = dataset.split(seed=7)
    b = dataset.split(seed=7)
    c = dataset.split(seed=9)

    ids_a = [x.example_id for x in a["train"] + a["val"] + a["test"]]
    ids_b = [x.example_id for x in b["train"] + b["val"] + b["test"]]
    ids_c = [x.example_id for x in c["train"] + c["val"] + c["test"]]

    assert len(ids_a) == 10
    assert sorted(ids_a) == sorted(ids_b) == sorted(ids_c)
    assert ids_a == ids_b
    assert ids_a != ids_c


def test_target_balance_report_marks_underfilled_categories() -> None:
    dataset = LatticeTrainingDataset()
    dataset.add([_example("ex-1", LatticeTrainingCategory.MANDATE_TO_BUNDLE)])
    report = dataset.target_balance_report()

    assert report["MANDATE_TO_BUNDLE"]["count"] == 1
    assert report["MANDATE_TO_BUNDLE"]["within_target"] is False
    assert report["TRIPWIRE_SPECIFICATION"]["count"] == 0


def test_factory_helpers_emit_expected_categories() -> None:
    tx = translation_example(
        example_id="tx-1",
        mandate_as_code={"mandate_id": "M-1"},
        action_bundle={"bundle_id": "B-1"},
        confidence_scores={"composite": 0.8},
        rationale="baseline",
    )
    repl = rejection_replan_example(
        example_id="rp-1",
        original_bundle={"bundle_id": "B-1"},
        governance_verdict="BLOCK",
        rejection_reason="scope_violation",
        replanned_bundle={"bundle_id": "B-1R"},
        replan_rationale="reduced scope",
        outcome="ALLOW",
    )
    esc = escalation_packaging_example(
        example_id="es-1",
        operation_context={"op": "scan"},
        escalation_trigger="CONFIDENCE_THRESHOLD",
        escalation_package={"decision_required": "approve?"},
        human_response={"decision": "A"},
        post_response_action={"action": "CONTINUE"},
    )

    assert tx.category == LatticeTrainingCategory.MANDATE_TO_BUNDLE
    assert repl.category == LatticeTrainingCategory.REJECTION_REPLAN
    assert esc.category == LatticeTrainingCategory.HITL_ESCALATION_PACKAGING
