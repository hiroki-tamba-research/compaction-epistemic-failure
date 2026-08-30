from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any


EXPECTED = {
    "positive_verified": "VERIFIED",
    "nonzero_exit_143": "REJECTED",
    "missing_exit": "UNKNOWN",
    "sequence_gap": "UNKNOWN",
    "producer_mismatch": "UNKNOWN",
    "model_text_only": "OBSERVED",
    "rule_version_mismatch": "UNKNOWN",
    "generation_mismatch": "UNKNOWN",
    "missing_artifact": "UNKNOWN",
    "hash_mismatch": "REJECTED",
    "claim_value_hash_mismatch": "REJECTED",
    "semantic_canary_missing": "REJECTED",
    "stored_no_checker": "STORED",
    "hash_only_no_semantics": "STORED",
    "unknown_checker": "UNKNOWN",
    "policy_missing": "UNKNOWN",
    "json_schema_pass": "VERIFIED",
    "json_schema_fail": "REJECTED",
    "path_escape": "REJECTED",
}
VALID_REPETITIONS = frozenset({1, 2, 3})
EXPECTED_PROBES = frozenset({
    "nonzero_exit_propagation",
    "expected_mismatch_detection",
    "missing_result_schema_detection",
    "corrupt_journal_classification",
    "journal_hash_tamper_classification",
    "corrupt_policy_classification",
    "nonobject_policy_classification",
    "nonobject_journal_payload_classification",
})
EVIDENCE_RECORD_FIELDS = frozenset({
    "record_id",
    "run_id",
    "generation_id",
    "subject",
    "predicate",
    "value_hash",
    "producer_identity",
    "bound_producer_identity",
    "producer_exit_status",
    "source_kind",
    "event_count",
    "event_sequence",
    "rule_version",
    "artifacts",
})
EVIDENCE_STRING_FIELDS = frozenset({
    "record_id",
    "run_id",
    "generation_id",
    "subject",
    "predicate",
    "producer_identity",
    "bound_producer_identity",
    "source_kind",
    "rule_version",
})
PROBE_DIRECTORIES = {
    "nonzero_exit_propagation": "apparatus-nonzero-exit",
    "expected_mismatch_detection": "apparatus-expected-mismatch",
    "missing_result_schema_detection": "apparatus-missing-result-schema",
    "corrupt_journal_classification": "apparatus-corrupt-journal",
    "journal_hash_tamper_classification": "apparatus-hash-tamper",
    "corrupt_policy_classification": "apparatus-corrupt-policy",
    "nonobject_policy_classification": "apparatus-nonobject-policy",
    "nonobject_journal_payload_classification": "apparatus-nonobject-journal-payload",
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def load_jsonl_objects(path: Path) -> list[dict[str, Any]]:
    values: list[dict[str, Any]] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        value = json.loads(line)
        if not isinstance(value, dict):
            raise ValueError(f"expected JSON object: {path}:{line_number}")
        values.append(value)
    return values


def is_sha256_hex(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdefABCDEF" for character in value)
    )


def validate_evidence_record_schema(record: dict[str, Any]) -> None:
    missing = sorted(EVIDENCE_RECORD_FIELDS.difference(record))
    if missing:
        raise ValueError(f"missing evidence fields: {','.join(missing)}")
    for field_name in EVIDENCE_STRING_FIELDS:
        if not isinstance(record[field_name], str):
            raise ValueError(f"{field_name} must be a string")
    if not is_sha256_hex(record["value_hash"]):
        raise ValueError("value_hash must be a SHA-256 hex digest")
    exit_status = record["producer_exit_status"]
    if exit_status is not None and type(exit_status) is not int:
        raise ValueError("producer_exit_status must be an integer or null")
    if type(record["event_count"]) is not int:
        raise ValueError("event_count must be an integer")
    event_sequence = record["event_sequence"]
    if not isinstance(event_sequence, list) or any(
        type(item) is not int for item in event_sequence
    ):
        raise ValueError("event_sequence must be an array of integers")
    artifacts = record["artifacts"]
    if not isinstance(artifacts, list):
        raise ValueError("artifacts must be an array")
    for index, artifact in enumerate(artifacts):
        if not isinstance(artifact, dict):
            raise ValueError(f"artifact-{index} must be a JSON object")
        if "relative_path" not in artifact or "sha256" not in artifact:
            raise ValueError(f"artifact-{index} is missing required fields")
        if not isinstance(artifact["relative_path"], str):
            raise ValueError(f"artifact-{index} relative_path must be a string")
        if not is_sha256_hex(artifact["sha256"]):
            raise ValueError(f"artifact-{index} sha256 must be a SHA-256 hex digest")


def load_verification_rule(path: Path, record_id: str) -> dict[str, Any] | None:
    policy = load_json(path)
    if policy.get("policy_version") != "IERL-POLICY-1" or not isinstance(
        policy.get("rules"), dict
    ):
        raise ValueError(f"invalid verification policy: {path}")
    raw_rule = policy["rules"].get(record_id)
    if raw_rule is None:
        return None
    if not isinstance(raw_rule, dict):
        raise ValueError(f"verification rule must be an object: {path}")
    if not isinstance(raw_rule.get("record_id"), str) or not isinstance(
        raw_rule.get("checker"), str
    ):
        raise ValueError(f"invalid verification rule identity: {path}")
    required_keys = raw_rule.get("required_keys", [])
    if not isinstance(required_keys, list) or any(
        not isinstance(item, str) for item in required_keys
    ):
        raise ValueError(f"invalid required_keys: {path}")
    expected_text = raw_rule.get("expected_text")
    if expected_text is not None and not isinstance(expected_text, str):
        raise ValueError(f"invalid expected_text: {path}")
    return raw_rule


def independent_case_resolution(
    record: dict[str, Any], artifact_root: Path, current_generation_id: str,
    verification_rule: dict[str, Any] | None,
) -> dict[str, Any]:
    def result(resolution: str, reason: str, checked: int = 0) -> dict[str, Any]:
        return {
            "record_id": record["record_id"],
            "resolution": resolution,
            "reason_code": reason,
            "rule_version": "IERL-1",
            "checked_artifacts": checked,
        }

    if record["source_kind"] == "model_text":
        return result("OBSERVED", "MODEL_TEXT_NOT_EVIDENCE")
    if record["rule_version"] != "IERL-1":
        return result("UNKNOWN", "RULE_VERSION_MISMATCH")
    if record["run_id"] != "run-conformance":
        return result("UNKNOWN", "RUN_SCOPE_MISMATCH")
    if record["generation_id"] != current_generation_id:
        return result("UNKNOWN", "GENERATION_SCOPE_MISMATCH")
    expected_sequence = list(range(1, record["event_count"] + 1))
    if record["event_count"] < 1 or record["event_sequence"] != expected_sequence:
        return result("UNKNOWN", "EVENT_SEQUENCE_INCOMPLETE")
    if (
        not record["producer_identity"]
        or record["producer_identity"] != record["bound_producer_identity"]
    ):
        return result("UNKNOWN", "PRODUCER_IDENTITY_UNBOUND")
    if record["producer_exit_status"] is None:
        return result("UNKNOWN", "EXIT_STATUS_MISSING")
    if record["producer_exit_status"] != 0:
        return result("REJECTED", "PRODUCER_NONZERO_EXIT")
    if not record["artifacts"]:
        return result("UNKNOWN", "ARTIFACTS_MISSING")
    if len(record["artifacts"]) != 1:
        return result("UNKNOWN", "ARTIFACT_CARDINALITY_UNSUPPORTED")
    if verification_rule is None or verification_rule["record_id"] != record["record_id"]:
        return result("UNKNOWN", "VERIFICATION_RULE_MISSING")

    root = artifact_root.resolve()
    checked = 0
    has_semantic_checker = False
    for artifact in record["artifacts"]:
        candidate = (root / artifact["relative_path"]).resolve()
        try:
            candidate.relative_to(root)
        except ValueError:
            return result("REJECTED", "ARTIFACT_PATH_ESCAPE", checked)
        if not candidate.is_file():
            return result("UNKNOWN", "ARTIFACT_FILE_MISSING", checked)
        try:
            content = candidate.read_bytes()
        except OSError:
            return result("UNKNOWN", "ARTIFACT_FILE_UNREADABLE", checked)
        digest = hashlib.sha256(content).hexdigest()
        if digest != artifact["sha256"].lower():
            return result("REJECTED", "ARTIFACT_HASH_MISMATCH", checked)
        if artifact["sha256"].lower() != record["value_hash"].lower():
            return result("REJECTED", "CLAIM_VALUE_HASH_MISMATCH", checked)
        checked += 1
        checker = verification_rule["checker"]
        if checker in {"none", "hash_only"}:
            continue
        if checker == "contains_utf8":
            has_semantic_checker = True
            try:
                text = content.decode("utf-8")
            except UnicodeDecodeError:
                return result("REJECTED", "UTF8_CHECK_FAILED", checked)
            expected_text = verification_rule.get("expected_text")
            if expected_text is None or expected_text not in text:
                return result("REJECTED", "TEXT_CHECK_FAILED", checked)
            continue
        if checker == "json_object_keys":
            has_semantic_checker = True
            try:
                value = json.loads(content)
            except (UnicodeDecodeError, json.JSONDecodeError):
                return result("REJECTED", "JSON_CHECK_FAILED", checked)
            if not isinstance(value, dict) or not set(
                verification_rule.get("required_keys", [])
            ).issubset(value):
                return result("REJECTED", "JSON_CHECK_FAILED", checked)
            continue
        return result("UNKNOWN", "CHECKER_UNRECOGNIZED", checked)
    if not has_semantic_checker:
        return result("STORED", "NO_SEMANTIC_CHECKER", checked)
    return result("VERIFIED", "ALL_REQUIREMENTS_SATISFIED", checked)


def case_fixture_errors(
    case_id: str,
    record: dict[str, Any],
    artifact_root: Path,
    current_generation_id: str,
    verification_rule: dict[str, Any] | None,
) -> list[str]:
    errors: list[str] = []
    expected_record_id = f"record-{case_id}"
    if record["record_id"] != expected_record_id:
        errors.append("record_id")
    if record["run_id"] != "run-conformance":
        errors.append("run_id")
    if record["generation_id"] != "generation-1":
        errors.append("record_generation")
    expected_current_generation = (
        "generation-2" if case_id == "generation_mismatch" else "generation-1"
    )
    if current_generation_id != expected_current_generation:
        errors.append("current_generation")
    if record["subject"] != "fixture" or record["predicate"] != "contains_canary":
        errors.append("claim_identity")
    expected_source = "model_text" if case_id == "model_text_only" else "artifact"
    if record["source_kind"] != expected_source:
        errors.append("source_kind")
    expected_rule_version = "UNKNOWN-9" if case_id == "rule_version_mismatch" else "IERL-1"
    if record["rule_version"] != expected_rule_version:
        errors.append("rule_version")
    expected_exit = None if case_id == "missing_exit" else (143 if case_id == "nonzero_exit_143" else 0)
    if record["producer_exit_status"] != expected_exit:
        errors.append("producer_exit_status")
    expected_sequence = [1, 3] if case_id == "sequence_gap" else [1, 2, 3]
    if record["event_count"] != 3 or record["event_sequence"] != expected_sequence:
        errors.append("event_sequence")
    if len(record["artifacts"]) != 1:
        errors.append("artifact_cardinality")
        return errors
    artifact = record["artifacts"][0]
    expected_path = "../outside.txt" if case_id == "path_escape" else "artifact.txt"
    if artifact["relative_path"] != expected_path:
        errors.append("artifact_path")
    root = artifact_root.resolve()
    candidate = (root / artifact["relative_path"]).resolve()
    inside = True
    try:
        candidate.relative_to(root)
    except ValueError:
        inside = False
    if case_id == "path_escape":
        if inside:
            errors.append("path_escape_missing")
        return errors
    if not inside:
        errors.append("unexpected_path_escape")
        return errors
    exists = candidate.is_file()
    if case_id == "missing_artifact":
        if exists:
            errors.append("missing_artifact_not_exercised")
        return errors
    if not exists:
        errors.append("artifact_missing")
        return errors
    content = candidate.read_bytes()
    digest = hashlib.sha256(content).hexdigest()
    artifact_hash_matches = digest == artifact["sha256"].lower()
    value_hash_matches = artifact["sha256"].lower() == record["value_hash"].lower()
    if case_id == "hash_mismatch":
        if artifact_hash_matches:
            errors.append("hash_mismatch_not_exercised")
        return errors
    if not artifact_hash_matches:
        errors.append("unexpected_artifact_hash_mismatch")
    if case_id == "claim_value_hash_mismatch":
        if value_hash_matches or record["value_hash"] != "0" * 64:
            errors.append("claim_value_mismatch_not_exercised")
    elif not value_hash_matches:
        errors.append("unexpected_claim_value_mismatch")

    expected_checker = {
        "stored_no_checker": "none",
        "hash_only_no_semantics": "hash_only",
        "unknown_checker": "model_judgment",
        "json_schema_pass": "json_object_keys",
        "json_schema_fail": "json_object_keys",
    }.get(case_id, "contains_utf8")
    if case_id == "policy_missing":
        if verification_rule is not None:
            errors.append("policy_missing_not_exercised")
        return errors
    if verification_rule is None or verification_rule.get("checker") != expected_checker:
        errors.append("checker")
        return errors
    if expected_checker == "contains_utf8":
        expected_text = f"CANARY::{case_id}::IERL-1"
        if verification_rule.get("expected_text") != expected_text:
            errors.append("expected_text")
        text = content.decode("utf-8")
        contains = expected_text in text
        if case_id == "semantic_canary_missing":
            if contains:
                errors.append("semantic_failure_not_exercised")
        elif not contains:
            errors.append("unexpected_semantic_failure")
    elif expected_checker == "json_object_keys":
        if verification_rule.get("required_keys") != ["canary", "ok"]:
            errors.append("required_keys")
        value = json.loads(content)
        has_keys = isinstance(value, dict) and {"canary", "ok"}.issubset(value)
        if case_id == "json_schema_pass" and not has_keys:
            errors.append("json_pass_not_exercised")
        if case_id == "json_schema_fail" and has_keys:
            errors.append("json_failure_not_exercised")
    return errors


def load_journal_record(path: Path) -> dict[str, Any]:
    entries = load_jsonl_objects(path)
    if len(entries) != 1:
        raise ValueError(f"expected one journal entry: {path}")
    entry = entries[0]
    required = {"sequence", "previous_hash", "payload", "entry_hash"}
    if not required.issubset(entry):
        raise ValueError(f"invalid journal envelope: {path}")
    if type(entry["sequence"]) is not int or entry["sequence"] != 1:
        raise ValueError(f"invalid journal sequence: {path}")
    previous_hash = entry["previous_hash"]
    entry_hash = entry["entry_hash"]
    if not isinstance(previous_hash, str) or previous_hash != "0" * 64:
        raise ValueError(f"invalid journal previous hash: {path}")
    if (
        not isinstance(entry_hash, str)
        or len(entry_hash) != 64
        or any(character not in "0123456789abcdef" for character in entry_hash)
    ):
        raise ValueError(f"invalid journal entry hash: {path}")
    unsigned = {
        "sequence": entry["sequence"],
        "previous_hash": previous_hash,
        "payload": entry["payload"],
    }
    calculated = hashlib.sha256(
        json.dumps(
            unsigned, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
    ).hexdigest()
    if entry_hash != calculated:
        raise ValueError(f"journal entry hash mismatch: {path}")
    payload = entry.get("payload")
    if not isinstance(payload, dict) or payload.get("event_type") != "evidence_record":
        raise ValueError(f"expected evidence payload: {path}")
    record = payload.get("record")
    if not isinstance(record, dict):
        raise ValueError(f"expected evidence record: {path}")
    validate_evidence_record_schema(record)
    return record


def repetition_matrix_errors(cases: list[dict[str, Any]]) -> list[str]:
    counts: Counter[tuple[str, int]] = Counter()
    errors: list[str] = []
    for index, case in enumerate(cases, start=1):
        case_id = case.get("case_id")
        repetition = case.get("repetition")
        if not isinstance(case_id, str) or case_id not in EXPECTED:
            errors.append(f"case-{index}:unexpected_case")
            continue
        if type(repetition) is not int or repetition not in VALID_REPETITIONS:
            errors.append(f"{case_id}:invalid_repetition:{repetition}")
            continue
        counts[(case_id, repetition)] += 1
    for case_id in sorted(EXPECTED):
        for repetition in sorted(VALID_REPETITIONS):
            count = counts[(case_id, repetition)]
            if count != 1:
                errors.append(f"{case_id}/rep-{repetition}:coordinate_count:{count}")
    return errors


def journal_identity_errors(
    case_id: str, record: dict[str, Any], producer: dict[str, Any]
) -> list[str]:
    pid = producer.get("pid")
    nonce = producer.get("nonce")
    if type(pid) is not int or not isinstance(nonce, str) or not nonce:
        return ["producer_identity_source"]
    raw_identity = f"pid:{pid};nonce:{nonce}"
    expected_producer = "unbound-producer" if case_id == "producer_mismatch" else raw_identity
    errors: list[str] = []
    if record.get("producer_identity") != expected_producer:
        errors.append("journal_producer_identity_binding")
    if record.get("bound_producer_identity") != raw_identity:
        errors.append("journal_bound_producer_identity_binding")
    return errors


def apparatus_probe_errors(probes: list[dict[str, Any]]) -> list[str]:
    counts: Counter[str] = Counter()
    errors: list[str] = []
    for index, probe in enumerate(probes, start=1):
        name = probe.get("probe")
        if not isinstance(name, str) or name not in EXPECTED_PROBES:
            errors.append(f"probe-{index}:unexpected_probe")
            continue
        counts[name] += 1
        if probe.get("pass") is not True:
            errors.append(f"{name}:controller_nonpass")
        if not apparatus_probe_semantics_ok(name, probe):
            errors.append(f"{name}:semantic_mismatch")
    for name in sorted(EXPECTED_PROBES):
        count = counts[name]
        if count != 1:
            errors.append(f"{name}:probe_count:{count}")
    return errors


def apparatus_probe_semantics_ok(name: str, probe: dict[str, Any]) -> bool:
    if name == "nonzero_exit_propagation":
        return probe.get("expected") == 37 and probe.get("actual") == 37
    if name in {"expected_mismatch_detection", "missing_result_schema_detection"}:
        return probe.get("expected") is True and probe.get("actual") is True
    if name == "corrupt_journal_classification":
        return (
            probe.get("expected_exit") == 70
            and probe.get("actual_exit") == 70
            and probe.get("expected_classification") == "HARNESS_DEFECT"
            and probe.get("actual_classification") == "HARNESS_DEFECT"
            and probe.get("stderr") == ""
        )
    if name == "journal_hash_tamper_classification":
        return (
            probe.get("expected_exit") == 70
            and probe.get("actual_exit") == 70
            and probe.get("expected_classification") == "HARNESS_DEFECT"
            and probe.get("actual_classification") == "HARNESS_DEFECT"
            and probe.get("expected_error_code") == "JOURNAL_HASH"
            and probe.get("actual_error_code") == "JOURNAL_HASH"
            and probe.get("stderr") == ""
        )
    if name == "corrupt_policy_classification":
        return (
            probe.get("expected_exit") == 70
            and probe.get("actual_exit") == 70
            and probe.get("expected_classification") == "HARNESS_DEFECT"
            and probe.get("actual_classification") == "HARNESS_DEFECT"
            and probe.get("stderr") == ""
        )
    expected_error_codes = {
        "nonobject_policy_classification": "EVIDENCE_SCHEMA",
        "nonobject_journal_payload_classification": "JOURNAL_SCHEMA",
    }
    if name in expected_error_codes:
        error_code = expected_error_codes[name]
        return (
            probe.get("expected_exit") == 70
            and probe.get("actual_exit") == 70
            and probe.get("expected_classification") == "HARNESS_DEFECT"
            and probe.get("actual_classification") == "HARNESS_DEFECT"
            and probe.get("expected_error_code") == error_code
            and probe.get("actual_error_code") == error_code
            and probe.get("stderr") == ""
        )
    return False


def comparison_detects_mismatch(fixture: dict[str, Any]) -> bool:
    expected = fixture.get("expected_resolution")
    document = fixture.get("document")
    exit_code = fixture.get("exit_code")
    if not isinstance(expected, str) or not isinstance(document, dict) or type(exit_code) is not int:
        raise ValueError("invalid comparison probe fixture")
    results = document.get("results") or []
    actual = results[-1].get("resolution") if results and isinstance(results[-1], dict) else None
    matched = (
        exit_code == 0
        and document.get("classification") == "RESOLUTION"
        and document.get("rule_version") == "IERL-1"
        and actual == expected
    )
    return not matched


def negative_probe_fixture_ok(name: str, probe_dir: Path) -> bool:
    journal_path = probe_dir / "journal.jsonl"
    policy_path = probe_dir / "policy.json"
    if name == "corrupt_journal_classification":
        try:
            json.loads(journal_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return True
        return False
    if name == "journal_hash_tamper_classification":
        try:
            load_journal_record(journal_path)
        except ValueError as exc:
            return "journal entry hash mismatch" in str(exc)
        return False
    if name == "corrupt_policy_classification":
        try:
            json.loads(policy_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return True
        return False
    if name == "nonobject_policy_classification":
        policy = json.loads(policy_path.read_text(encoding="utf-8"))
        return not isinstance(policy, dict)
    if name == "nonobject_journal_payload_classification":
        entries = load_jsonl_objects(journal_path)
        if len(entries) != 1:
            return False
        entry = entries[0]
        unsigned = {
            "sequence": entry.get("sequence"),
            "previous_hash": entry.get("previous_hash"),
            "payload": entry.get("payload"),
        }
        calculated = hashlib.sha256(
            json.dumps(
                unsigned, ensure_ascii=False, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
        ).hexdigest()
        return (
            type(entry.get("sequence")) is int
            and entry.get("sequence") == 1
            and entry.get("previous_hash") == "0" * 64
            and entry.get("entry_hash") == calculated
            and not isinstance(entry.get("payload"), dict)
        )
    return False


def probe_raw_errors(
    run_root: Path, probe: dict[str, Any]
) -> list[str]:
    name = probe.get("probe")
    if not isinstance(name, str) or name not in PROBE_DIRECTORIES:
        return []
    expected_dir = PROBE_DIRECTORIES[name]
    errors: list[str] = []
    if probe.get("probe_dir") != expected_dir:
        errors.append(f"{name}:probe_dir_binding")
    probe_dir = run_root / expected_dir
    try:
        if name in {"expected_mismatch_detection", "missing_result_schema_detection"}:
            fixture = load_json(probe_dir / "input.json")
            if comparison_detects_mismatch(fixture) is not True:
                errors.append(f"{name}:raw_fixture_semantics")
            document = fixture.get("document")
            if not isinstance(document, dict):
                errors.append(f"{name}:raw_fixture_shape")
            elif name == "expected_mismatch_detection":
                results = document.get("results")
                if (
                    document.get("classification") != "RESOLUTION"
                    or document.get("rule_version") != "IERL-1"
                    or not isinstance(results, list)
                    or len(results) != 1
                    or not isinstance(results[0], dict)
                    or results[0].get("resolution") != "REJECTED"
                ):
                    errors.append(f"{name}:raw_fixture_shape")
            elif "results" in document:
                errors.append(f"{name}:raw_fixture_shape")
            if probe.get("actual") is not True:
                errors.append(f"{name}:raw_event_binding")
            return errors

        exit_document = load_json(probe_dir / "resolver.exit.json")
        raw_exit = exit_document.get("exit_code")
        raw_pid = exit_document.get("child_pid")
        stdout_text = (probe_dir / "resolver.stdout.json").read_text(encoding="utf-8").strip()
        stderr_text = (probe_dir / "resolver.stderr.txt").read_text(encoding="utf-8").strip()
        if type(raw_exit) is not int or type(raw_pid) is not int:
            errors.append(f"{name}:raw_process_schema")
            return errors
        if probe.get("child_pid") != raw_pid:
            errors.append(f"{name}:raw_pid_binding")
        if name == "nonzero_exit_propagation":
            if raw_exit != 37 or stdout_text or stderr_text:
                errors.append(f"{name}:raw_process_outcome")
            if probe.get("actual") != raw_exit:
                errors.append(f"{name}:raw_event_binding")
            return errors

        document = json.loads(stdout_text)
        if not isinstance(document, dict):
            raise ValueError("probe stdout is not an object")
        if document.get("process_id") != raw_pid:
            errors.append(f"{name}:raw_stdout_pid_binding")
        expected_codes = {
            "corrupt_journal_classification": "JOURNAL_PARSE",
            "journal_hash_tamper_classification": "JOURNAL_HASH",
            "corrupt_policy_classification": "EVIDENCE_SCHEMA",
            "nonobject_policy_classification": "EVIDENCE_SCHEMA",
            "nonobject_journal_payload_classification": "JOURNAL_SCHEMA",
        }
        expected_code = expected_codes[name]
        if (
            raw_exit != 70
            or stderr_text
            or document.get("classification") != "HARNESS_DEFECT"
            or document.get("error_code") != expected_code
        ):
            errors.append(f"{name}:raw_process_outcome")
        if (
            probe.get("actual_exit") != raw_exit
            or probe.get("actual_classification") != document.get("classification")
            or ("actual_error_code" in probe and probe.get("actual_error_code") != document.get("error_code"))
            or probe.get("stderr") != stderr_text
        ):
            errors.append(f"{name}:raw_event_binding")
        if not negative_probe_fixture_ok(name, probe_dir):
            errors.append(f"{name}:raw_fixture_semantics")
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        errors.append(f"{name}:raw_probe:{exc}")
    return errors


def audit(run_root: Path) -> dict[str, Any]:
    errors: list[str] = []
    try:
        summary = load_json(run_root / "summary.json")
        events = load_jsonl_objects(run_root / "events.jsonl")
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return {"overall": "FAIL", "errors": [f"run_parse:{exc}"]}
    cases = [event for event in events if event.get("event_type") == "case_completed"]
    probes = [event for event in events if event.get("event_type") == "apparatus_probe"]
    errors.extend(repetition_matrix_errors(cases))
    errors.extend(apparatus_probe_errors(probes))
    for probe in probes:
        errors.extend(probe_raw_errors(run_root, probe))
    distribution: Counter[str] = Counter()
    for case in cases:
        case_id = case.get("case_id")
        repetition = case.get("repetition")
        if not isinstance(case_id, str) or case_id not in EXPECTED:
            continue
        if type(repetition) is not int or repetition not in VALID_REPETITIONS:
            continue
        expected = EXPECTED.get(case_id)
        actual = case.get("actual_resolution")
        distribution[str(actual)] += 1
        label = f"{case_id}/rep-{repetition}"
        if expected is None:
            errors.append(f"{label}:unexpected_case")
        if case.get("expected_resolution") != expected:
            errors.append(f"{label}:controller_expected_differs_from_auditor")
        if actual != expected:
            errors.append(f"{label}:resolution_mismatch")
        if case.get("pass") is not True:
            errors.append(f"{label}:controller_marked_nonpass")
        case_dir = run_root / "cases" / case_id / f"rep-{repetition}"
        try:
            producer = load_json(case_dir / "producer.stdout.json")
            resolver = load_json(case_dir / "resolver.stdout.json")
            journal_record = load_journal_record(case_dir / "journal.jsonl")
            verification_rule = load_verification_rule(
                case_dir / "policy.json", journal_record["record_id"]
            )
            current_generation = (
                "generation-2" if case_id == "generation_mismatch" else "generation-1"
            )
            for fixture_error in case_fixture_errors(
                case_id,
                journal_record,
                case_dir / "artifacts",
                current_generation,
                verification_rule,
            ):
                errors.append(f"{label}:fixture:{fixture_error}")
            independently_resolved = independent_case_resolution(
                journal_record,
                case_dir / "artifacts",
                current_generation,
                verification_rule,
            )
            results = resolver.get("results") or []
            raw_result = results[-1] if results and isinstance(results[-1], dict) else {}
            raw_actual = raw_result.get("resolution")
            if producer.get("pid") != case.get("producer_pid"):
                errors.append(f"{label}:producer_pid_binding")
            if resolver.get("process_id") != case.get("child_pid"):
                errors.append(f"{label}:resolver_pid_binding")
            raw_identity = f"pid:{producer.get('pid')};nonce:{producer.get('nonce')}"
            if case.get("producer_identity") != raw_identity:
                errors.append(f"{label}:event_producer_identity_binding")
            for identity_error in journal_identity_errors(case_id, journal_record, producer):
                errors.append(f"{label}:{identity_error}")
            if raw_actual != actual:
                errors.append(f"{label}:raw_resolution_binding")
            if independently_resolved["resolution"] != expected:
                errors.append(f"{label}:independent_resolution_mismatch")
            if raw_result != independently_resolved:
                errors.append(f"{label}:resolver_oracle_mismatch")
            if sha256_file(case_dir / "journal.jsonl") != case.get("journal_sha256"):
                errors.append(f"{label}:journal_hash")
            if sha256_file(case_dir / "policy.json") != case.get("policy_sha256"):
                errors.append(f"{label}:policy_hash")
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            errors.append(f"{label}:raw_evidence:{exc}")

    if len(cases) != 57:
        errors.append(f"case_count:{len(cases)}")
    if len(probes) != len(EXPECTED_PROBES):
        errors.append(f"apparatus_probe_count:{len(probes)}")
    if summary.get("codex_target_runs") != 0:
        errors.append("codex_target_run_detected")
    if summary.get("model_output_used_as_evidence") is not False:
        errors.append("model_output_evidence_detected")

    manifest_path = run_root / "SHA256SUMS.txt"
    listed: set[str] = set()
    try:
        for line in manifest_path.read_text(encoding="utf-8").splitlines():
            digest, separator, relative = line.partition("  ")
            if not separator or len(digest) != 64:
                errors.append("manifest_malformed")
                continue
            listed.add(relative)
            target = run_root / Path(relative)
            if not target.is_file() or sha256_file(target) != digest:
                errors.append(f"manifest_hash:{relative}")
        actual_files = {
            path.relative_to(run_root).as_posix()
            for path in run_root.rglob("*")
            if path.is_file() and path != manifest_path
        }
        if listed != actual_files:
            errors.append("manifest_closure")
    except OSError as exc:
        errors.append(f"manifest_read:{exc}")

    return {
        "overall": "PASS" if not errors else "FAIL",
        "run_root": str(run_root.resolve()),
        "errors": errors,
        "case_count": len(cases),
        "apparatus_probe_count": len(probes),
        "resolution_distribution": dict(sorted(distribution.items())),
        "manifest_entries": len(listed),
        "auditor_expected_cases": len(EXPECTED),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("run_root", type=Path)
    args = parser.parse_args()
    report = audit(args.run_root)
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if report["overall"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
