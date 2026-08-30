from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .model import EvidenceRecord, ResolutionResult, VerificationRule


RULE_VERSION = "IERL-1"


def _result(record: EvidenceRecord, resolution: str, reason: str, checked: int = 0) -> ResolutionResult:
    return ResolutionResult(
        record_id=record.record_id,
        resolution=resolution,
        reason_code=reason,
        rule_version=RULE_VERSION,
        checked_artifacts=checked,
    )


def _inside_root(root: Path, candidate: Path) -> bool:
    try:
        candidate.relative_to(root)
        return True
    except ValueError:
        return False


def resolve_record(
    record: EvidenceRecord,
    artifact_root: Path,
    current_run_id: str,
    current_generation_id: str,
    verification_rule: VerificationRule | None,
) -> ResolutionResult:
    if record.source_kind == "model_text":
        return _result(record, "OBSERVED", "MODEL_TEXT_NOT_EVIDENCE")
    if record.rule_version != RULE_VERSION:
        return _result(record, "UNKNOWN", "RULE_VERSION_MISMATCH")
    if record.run_id != current_run_id:
        return _result(record, "UNKNOWN", "RUN_SCOPE_MISMATCH")
    if record.generation_id != current_generation_id:
        return _result(record, "UNKNOWN", "GENERATION_SCOPE_MISMATCH")
    expected_sequence = tuple(range(1, record.event_count + 1))
    if record.event_count < 1 or record.event_sequence != expected_sequence:
        return _result(record, "UNKNOWN", "EVENT_SEQUENCE_INCOMPLETE")
    if not record.producer_identity or record.producer_identity != record.bound_producer_identity:
        return _result(record, "UNKNOWN", "PRODUCER_IDENTITY_UNBOUND")
    if record.producer_exit_status is None:
        return _result(record, "UNKNOWN", "EXIT_STATUS_MISSING")
    if record.producer_exit_status != 0:
        return _result(record, "REJECTED", "PRODUCER_NONZERO_EXIT")
    if not record.artifacts:
        return _result(record, "UNKNOWN", "ARTIFACTS_MISSING")
    if len(record.artifacts) != 1:
        return _result(record, "UNKNOWN", "ARTIFACT_CARDINALITY_UNSUPPORTED")
    if verification_rule is None or verification_rule.record_id != record.record_id:
        return _result(record, "UNKNOWN", "VERIFICATION_RULE_MISSING")

    root = Path(artifact_root).resolve()
    checked = 0
    has_semantic_checker = False
    for artifact in record.artifacts:
        candidate = (root / artifact.relative_path).resolve()
        if not _inside_root(root, candidate):
            return _result(record, "REJECTED", "ARTIFACT_PATH_ESCAPE", checked)
        if not candidate.is_file():
            return _result(record, "UNKNOWN", "ARTIFACT_FILE_MISSING", checked)
        try:
            content = candidate.read_bytes()
        except OSError:
            return _result(record, "UNKNOWN", "ARTIFACT_FILE_UNREADABLE", checked)
        digest = hashlib.sha256(content).hexdigest()
        if digest != artifact.sha256:
            return _result(record, "REJECTED", "ARTIFACT_HASH_MISMATCH", checked)
        if artifact.sha256 != record.value_hash:
            return _result(record, "REJECTED", "CLAIM_VALUE_HASH_MISMATCH", checked)
        checked += 1
        if verification_rule.checker in {"none", "hash_only"}:
            continue
        if verification_rule.checker == "contains_utf8":
            has_semantic_checker = True
            try:
                text = content.decode("utf-8")
            except UnicodeDecodeError:
                return _result(record, "REJECTED", "UTF8_CHECK_FAILED", checked)
            if verification_rule.expected_text is None or verification_rule.expected_text not in text:
                return _result(record, "REJECTED", "TEXT_CHECK_FAILED", checked)
            continue
        if verification_rule.checker == "json_object_keys":
            has_semantic_checker = True
            try:
                value = json.loads(content)
            except (UnicodeDecodeError, json.JSONDecodeError):
                return _result(record, "REJECTED", "JSON_CHECK_FAILED", checked)
            if not isinstance(value, dict) or not set(verification_rule.required_keys).issubset(value):
                return _result(record, "REJECTED", "JSON_CHECK_FAILED", checked)
            continue
        return _result(record, "UNKNOWN", "CHECKER_UNRECOGNIZED", checked)

    if not has_semantic_checker:
        return _result(record, "STORED", "NO_SEMANTIC_CHECKER", checked)
    return _result(record, "VERIFIED", "ALL_REQUIREMENTS_SATISFIED", checked)
