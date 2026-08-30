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
            results = resolver.get("results") or []
            raw_actual = results[-1].get("resolution") if results else None
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
