from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))
sys.path.insert(0, str(PROJECT_ROOT / "controller"))

from audit_run import (  # noqa: E402
    EXPECTED,
    EXPECTED_PROBES,
    apparatus_probe_errors,
    apparatus_probe_semantics_ok,
    journal_identity_errors,
    load_journal_record,
    repetition_matrix_errors,
    validate_evidence_record_schema,
)
from run_conformance import journal_envelope, load_stored_case_evidence  # noqa: E402
from evidence_resolution.cli import resolve_command  # noqa: E402
from evidence_resolution.model import EvidenceRecord, VerificationRule  # noqa: E402
from evidence_resolution.resolver import resolve_record  # noqa: E402
from evidence_resolution.store import (  # noqa: E402
    JournalError,
    JsonlJournal,
    canonical_json,
    sha256_bytes,
)


def record_for(content: bytes, **updates: object) -> EvidenceRecord:
    digest = hashlib.sha256(content).hexdigest()
    value = {
        "record_id": "r1",
        "run_id": "run-1",
        "generation_id": "g1",
        "subject": "fixture",
        "predicate": "contains_canary",
        "value_hash": digest,
        "producer_identity": "p1",
        "bound_producer_identity": "p1",
        "producer_exit_status": 0,
        "source_kind": "artifact",
        "event_count": 2,
        "event_sequence": [1, 2],
        "rule_version": "IERL-1",
        "artifacts": [{
            "relative_path": "artifact.txt",
            "sha256": digest,
        }],
    }
    value.update(updates)
    return EvidenceRecord.from_dict(value)


class ResolverTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.content = b"CANARY\n"
        (self.root / "artifact.txt").write_bytes(self.content)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def resolve(self, record: EvidenceRecord, rule: VerificationRule | None = None):
        rule = rule or VerificationRule(record_id=record.record_id, checker="contains_utf8", expected_text="CANARY")
        return resolve_record(record, self.root, "run-1", "g1", rule)

    def test_verified_requires_complete_evidence(self) -> None:
        self.assertEqual(self.resolve(record_for(self.content)).resolution, "VERIFIED")

    def test_nonzero_exit_rejected_even_with_artifact(self) -> None:
        record = record_for(self.content, producer_exit_status=143)
        self.assertEqual(self.resolve(record).resolution, "REJECTED")

    def test_model_text_never_verifies(self) -> None:
        record = record_for(self.content, source_kind="model_text")
        self.assertEqual(self.resolve(record).resolution, "OBSERVED")

    def test_missing_artifact_is_unknown(self) -> None:
        (self.root / "artifact.txt").unlink()
        self.assertEqual(self.resolve(record_for(self.content)).resolution, "UNKNOWN")

    def test_tampering_is_rejected(self) -> None:
        record = record_for(self.content)
        (self.root / "artifact.txt").write_bytes(b"changed")
        self.assertEqual(self.resolve(record).resolution, "REJECTED")

    def test_claim_value_hash_mismatch_is_rejected(self) -> None:
        record = record_for(self.content, value_hash="0" * 64)
        result = self.resolve(record)
        self.assertEqual(result.resolution, "REJECTED")
        self.assertEqual(result.reason_code, "CLAIM_VALUE_HASH_MISMATCH")

    def test_event_gap_is_unknown(self) -> None:
        record = record_for(self.content, event_sequence=[1, 3])
        self.assertEqual(self.resolve(record).resolution, "UNKNOWN")

    def test_missing_verification_policy_is_unknown(self) -> None:
        record = record_for(self.content)
        result = resolve_record(record, self.root, "run-1", "g1", None)
        self.assertEqual(result.resolution, "UNKNOWN")
        self.assertEqual(result.reason_code, "VERIFICATION_RULE_MISSING")

    def test_hash_correct_but_canary_missing_is_rejected(self) -> None:
        content = b"NO MARKER HERE\n"
        (self.root / "artifact.txt").write_bytes(content)
        record = record_for(content)
        result = self.resolve(record)
        self.assertEqual(result.resolution, "REJECTED")
        self.assertEqual(result.reason_code, "TEXT_CHECK_FAILED")

    def test_result_is_deterministic(self) -> None:
        record = record_for(self.content)
        first = self.resolve(record).to_dict()
        second = self.resolve(record).to_dict()
        self.assertEqual(first, second)


class JournalTests(unittest.TestCase):
    def test_append_readback_and_hash_chain(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            journal = JsonlJournal(Path(temporary) / "events.jsonl")
            first = journal.append({"event_type": "one"})
            second = journal.append({"event_type": "two"})
            self.assertEqual(second["previous_hash"], first["entry_hash"])
            self.assertEqual(len(journal.load()), 2)

    def test_corrupt_journal_is_apparatus_defect(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "events.jsonl"
            path.write_text("{broken}\n", encoding="utf-8")
            with self.assertRaises(JournalError) as caught:
                JsonlJournal(path).load()
            self.assertEqual(caught.exception.code, "JOURNAL_PARSE")

    def test_non_object_payload_is_apparatus_defect(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "events.jsonl"
            unsigned = {"sequence": 1, "previous_hash": "0" * 64, "payload": []}
            envelope = {**unsigned, "entry_hash": sha256_bytes(canonical_json(unsigned))}
            path.write_bytes(canonical_json(envelope) + b"\n")
            with self.assertRaises(JournalError) as caught:
                JsonlJournal(path).load()
            self.assertEqual(caught.exception.code, "JOURNAL_SCHEMA")

    def test_boolean_sequence_is_apparatus_defect(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "events.jsonl"
            unsigned = {"sequence": True, "previous_hash": "0" * 64, "payload": {}}
            envelope = {**unsigned, "entry_hash": sha256_bytes(canonical_json(unsigned))}
            path.write_bytes(canonical_json(envelope) + b"\n")
            with self.assertRaises(JournalError) as caught:
                JsonlJournal(path).load()
            self.assertEqual(caught.exception.code, "JOURNAL_SCHEMA")


class CliSchemaTests(unittest.TestCase):
    def test_non_object_policy_emits_structured_harness_defect(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            policy = root / "policy.json"
            policy.write_text("[]\n", encoding="utf-8")
            args = argparse.Namespace(
                policy=str(policy),
                journal=str(root / "journal.jsonl"),
                artifact_root=str(root),
                run_id="run-1",
                generation_id="g1",
            )
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                exit_code = resolve_command(args)
            document = json.loads(output.getvalue())
            self.assertEqual(exit_code, 70)
            self.assertEqual(document["classification"], "HARNESS_DEFECT")
            self.assertEqual(document["error_code"], "EVIDENCE_SCHEMA")

    def test_malformed_field_types_emit_structured_harness_defect(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            content = b"CANARY\n"
            (root / "artifact.txt").write_bytes(content)
            malformed = record_for(content).to_dict()
            malformed.update({
                "producer_identity": 123,
                "bound_producer_identity": "123",
                "producer_exit_status": False,
                "event_count": 3.9,
                "event_sequence": ["1", "2", "3"],
            })
            journal = JsonlJournal(root / "journal.jsonl")
            journal.append({"event_type": "evidence_record", "record": malformed})
            policy = {
                "policy_version": "IERL-POLICY-1",
                "rules": {
                    "r1": {
                        "record_id": "r1",
                        "checker": "contains_utf8",
                        "required_keys": [],
                        "expected_text": "CANARY",
                    }
                },
            }
            (root / "policy.json").write_text(json.dumps(policy), encoding="utf-8")
            args = argparse.Namespace(
                policy=str(root / "policy.json"),
                journal=str(root / "journal.jsonl"),
                artifact_root=str(root),
                run_id="run-1",
                generation_id="g1",
            )
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                exit_code = resolve_command(args)
            document = json.loads(output.getvalue())
            self.assertEqual(exit_code, 70)
            self.assertEqual(document["classification"], "HARNESS_DEFECT")


class AuditorRegressionTests(unittest.TestCase):
    def test_both_wrong_journal_identities_are_detected(self) -> None:
        record = {
            "producer_identity": "pid:999;nonce:wrong",
            "bound_producer_identity": "pid:999;nonce:wrong",
        }
        producer = {"pid": 123, "nonce": "positive_verified-rep-1"}
        self.assertEqual(
            journal_identity_errors("positive_verified", record, producer),
            [
                "journal_producer_identity_binding",
                "journal_bound_producer_identity_binding",
            ],
        )

    def test_duplicate_repetition_ids_are_detected(self) -> None:
        cases = []
        for case_id in sorted(EXPECTED):
            repetitions = [1, 1, 1] if case_id == "positive_verified" else [1, 2, 3]
            cases.extend({"case_id": case_id, "repetition": rep} for rep in repetitions)
        errors = repetition_matrix_errors(cases)
        self.assertIn("positive_verified/rep-1:coordinate_count:3", errors)
        self.assertIn("positive_verified/rep-2:coordinate_count:0", errors)
        self.assertIn("positive_verified/rep-3:coordinate_count:0", errors)

    def test_duplicate_probes_cannot_replace_required_probes(self) -> None:
        probes = [{"probe": name, "pass": True} for name in sorted(EXPECTED_PROBES)]
        probes[-2:] = [probes[0].copy(), probes[1].copy()]
        errors = apparatus_probe_errors(probes)
        self.assertTrue(any(error.endswith(":probe_count:0") for error in errors))
        self.assertTrue(any(error.endswith(":probe_count:2") for error in errors))

    def test_false_probe_pass_flag_is_independently_rejected(self) -> None:
        probe = {
            "probe": "nonobject_policy_classification",
            "expected_exit": 70,
            "actual_exit": 0,
            "expected_classification": "HARNESS_DEFECT",
            "actual_classification": "RESOLUTION",
            "expected_error_code": "EVIDENCE_SCHEMA",
            "actual_error_code": None,
            "stderr": "traceback",
            "pass": True,
        }
        self.assertFalse(apparatus_probe_semantics_ok(probe["probe"], probe))

    def test_auditor_recomputes_journal_entry_hash(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "journal.jsonl"
            payload = {"event_type": "evidence_record", "record": {}}
            envelope = journal_envelope(payload)
            envelope["entry_hash"] = "f" * 64
            path.write_text(json.dumps(envelope) + "\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                load_journal_record(path)

    def test_auditor_rejects_malformed_complete_record_schema(self) -> None:
        record = record_for(b"CANARY\n").to_dict()
        record["event_count"] = "3"
        with self.assertRaisesRegex(ValueError, "event_count must be an integer"):
            validate_evidence_record_schema(record)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "journal.jsonl"
            envelope = journal_envelope({"event_type": "evidence_record", "record": record})
            path.write_text(json.dumps(envelope) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "event_count must be an integer"):
                load_journal_record(path)

    def test_controller_captures_nonobject_case_journal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case_dir = Path(temporary)
            (case_dir / "producer.stdout.json").write_text("{}\n", encoding="utf-8")
            (case_dir / "journal.jsonl").write_text(
                json.dumps(journal_envelope([])) + "\n",  # type: ignore[arg-type]
                encoding="utf-8",
            )
            producer, record, error = load_stored_case_evidence(case_dir)
            self.assertEqual(producer, {})
            self.assertEqual(record, {})
            self.assertIn("journal payload is not an object", error or "")


if __name__ == "__main__":
    unittest.main()
