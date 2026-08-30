from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from evidence_resolution.model import EvidenceRecord, VerificationRule  # noqa: E402
from evidence_resolution.resolver import resolve_record  # noqa: E402
from evidence_resolution.store import JournalError, JsonlJournal  # noqa: E402


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


if __name__ == "__main__":
    unittest.main()
