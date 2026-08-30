from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = PROJECT_ROOT / "src"
RULE_VERSION = "IERL-1"
REPETITIONS = 3


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def append_event(path: Path, event: dict[str, Any]) -> None:
    with path.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(canonical_json(event) + "\n")
        handle.flush()
        os.fsync(handle.fileno())


def journal_envelope(payload: dict[str, Any], sequence: int = 1, previous: str | None = None) -> dict[str, Any]:
    unsigned = {
        "sequence": sequence,
        "previous_hash": previous or "0" * 64,
        "payload": payload,
    }
    return {**unsigned, "entry_hash": sha256_bytes(canonical_json(unsigned).encode("utf-8"))}


def write_journal(path: Path, record: dict[str, Any]) -> None:
    payload = {"event_type": "evidence_record", "record": record}
    path.write_text(canonical_json(journal_envelope(payload)) + "\n", encoding="utf-8")


def read_journal_record(path: Path) -> dict[str, Any]:
    envelope = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(envelope, dict):
        raise ValueError("journal envelope is not an object")
    payload = envelope.get("payload")
    if not isinstance(payload, dict):
        raise ValueError("journal payload is not an object")
    record = payload.get("record")
    if not isinstance(record, dict):
        raise ValueError("journal record is not an object")
    return record


def load_stored_case_evidence(
    case_dir: Path,
) -> tuple[dict[str, Any], dict[str, Any], str | None]:
    try:
        producer = json.loads((case_dir / "producer.stdout.json").read_text(encoding="utf-8"))
        if not isinstance(producer, dict):
            raise ValueError("producer output is not an object")
        record = read_journal_record(case_dir / "journal.jsonl")
        return producer, record, None
    except (OSError, ValueError, TypeError) as exc:
        return {}, {}, f"stored evidence: {exc}"


def write_policy(path: Path, record_id: str | None, rule: dict[str, Any] | None = None) -> None:
    rules = {}
    if record_id is not None:
        rules[record_id] = {
            "record_id": record_id,
            "checker": "contains_utf8",
            "required_keys": [],
            "expected_text": record_id.removeprefix("record-").join(("CANARY::", "::IERL-1")),
            **(rule or {}),
        }
    policy = {"policy_version": "IERL-POLICY-1", "rules": rules}
    path.write_text(canonical_json(policy) + "\n", encoding="utf-8")


def base_record(case_id: str, artifact_hash: str) -> dict[str, Any]:
    return {
        "record_id": f"record-{case_id}",
        "run_id": "run-conformance",
        "generation_id": "generation-1",
        "subject": "fixture",
        "predicate": "contains_canary",
        "value_hash": artifact_hash,
        "producer_identity": "synthetic-producer-1",
        "bound_producer_identity": "synthetic-producer-1",
        "producer_exit_status": 0,
        "source_kind": "artifact",
        "event_count": 3,
        "event_sequence": [1, 2, 3],
        "rule_version": RULE_VERSION,
        "artifacts": [
            {
                "relative_path": "artifact.txt",
                "sha256": artifact_hash,
            }
        ],
    }


def case_definitions() -> list[dict[str, Any]]:
    return [
        {"id": "positive_verified", "expected": "VERIFIED"},
        {"id": "nonzero_exit_143", "expected": "REJECTED", "producer_actual_exit": 143},
        {"id": "missing_exit", "expected": "UNKNOWN", "mutate": {"producer_exit_status": None}},
        {"id": "sequence_gap", "expected": "UNKNOWN", "mutate": {"event_sequence": [1, 3]}},
        {"id": "producer_mismatch", "expected": "UNKNOWN", "mutate": {"producer_identity": "unbound-producer"}},
        {"id": "model_text_only", "expected": "OBSERVED", "mutate": {"source_kind": "model_text"}},
        {"id": "rule_version_mismatch", "expected": "UNKNOWN", "mutate": {"rule_version": "UNKNOWN-9"}},
        {"id": "generation_mismatch", "expected": "UNKNOWN", "generation": "generation-2"},
        {"id": "missing_artifact", "expected": "UNKNOWN", "delete_artifact": True},
        {"id": "hash_mismatch", "expected": "REJECTED", "tamper_artifact": True},
        {"id": "claim_value_hash_mismatch", "expected": "REJECTED", "mutate": {"value_hash": "0" * 64}},
        {"id": "semantic_canary_missing", "expected": "REJECTED", "content": "NO MARKER HERE\n"},
        {"id": "stored_no_checker", "expected": "STORED", "policy_mutate": {"checker": "none"}},
        {"id": "hash_only_no_semantics", "expected": "STORED", "policy_mutate": {"checker": "hash_only"}},
        {"id": "unknown_checker", "expected": "UNKNOWN", "policy_mutate": {"checker": "model_judgment"}},
        {"id": "policy_missing", "expected": "UNKNOWN", "policy_missing": True},
        {"id": "json_schema_pass", "expected": "VERIFIED", "json": {"canary": "IERL", "ok": True}, "policy_mutate": {"checker": "json_object_keys", "required_keys": ["canary", "ok"], "expected_text": None}},
        {"id": "json_schema_fail", "expected": "REJECTED", "json": {"canary": "IERL"}, "policy_mutate": {"checker": "json_object_keys", "required_keys": ["canary", "ok"], "expected_text": None}},
        {"id": "path_escape", "expected": "REJECTED", "artifact_mutate": {"relative_path": "../outside.txt"}, "outside": True},
    ]


def launch_resolver(python: Path, case_dir: Path, generation: str) -> tuple[int, int, str, str]:
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(SOURCE_ROOT)
    command = [
        str(python), "-m", "evidence_resolution.cli", "resolve",
        "--journal", str(case_dir / "journal.jsonl"),
        "--artifact-root", str(case_dir / "artifacts"),
        "--policy", str(case_dir / "policy.json"),
        "--run-id", "run-conformance",
        "--generation-id", generation,
    ]
    child = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=environment)
    stdout, stderr = child.communicate(timeout=30)
    return child.pid, int(child.returncode), stdout.strip(), stderr.strip()


def normalize_result(document: dict[str, Any]) -> dict[str, Any]:
    return {
        "classification": document.get("classification"),
        "rule_version": document.get("rule_version"),
        "results": document.get("results"),
        "error_code": document.get("error_code"),
    }


def launch_producer(
    python: Path, case_dir: Path, definition: dict[str, Any], repetition: int
) -> dict[str, Any]:
    artifacts = case_dir / "artifacts"
    artifacts.mkdir(parents=True)
    if "json" in definition:
        content_text = canonical_json(definition["json"])
    elif "content" in definition:
        content_text = str(definition["content"])
    else:
        content_text = f"CANARY::{definition['id']}::IERL-1\n"
    artifact = artifacts / "artifact.txt"
    nonce = f"{definition['id']}-rep-{repetition}"
    producer_exit = int(definition.get("producer_actual_exit", 0))
    command = [
        str(python), str(PROJECT_ROOT / "controller" / "synthetic_producer.py"),
        "--output", str(artifact), "--nonce", nonce, "--content", content_text,
        "--exit-code", str(producer_exit),
    ]
    child = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    stdout, stderr = child.communicate(timeout=30)
    (case_dir / "producer.stdout.json").write_bytes(stdout.encode("utf-8"))
    (case_dir / "producer.stderr.txt").write_bytes(stderr.encode("utf-8"))
    (case_dir / "producer.exit.json").write_text(
        canonical_json({"child_pid": child.pid, "exit_code": int(child.returncode)}) + "\n",
        encoding="utf-8",
    )
    try:
        report = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"synthetic producer emitted invalid JSON: {exc}") from exc
    if report.get("pid") != child.pid or report.get("nonce") != nonce:
        raise RuntimeError("synthetic producer identity mismatch")
    if child.returncode != producer_exit or stderr:
        raise RuntimeError("synthetic producer outcome mismatch")
    return {
        "artifact": artifact,
        "content": content_text.encode("utf-8"),
        "sha256": report["sha256"],
        "producer_pid": child.pid,
        "producer_exit": child.returncode,
        "producer_identity": f"pid:{child.pid};nonce:{nonce}",
        "producer_stdout_sha256": sha256_bytes(stdout.encode("utf-8")),
    }


def prepare_case(
    python: Path, case_dir: Path, definition: dict[str, Any], repetition: int
) -> dict[str, Any]:
    producer = launch_producer(python, case_dir, definition, repetition)
    artifact = producer["artifact"]
    content = producer["content"]
    digest = producer["sha256"]
    record = base_record(definition["id"], digest)
    record["producer_identity"] = producer["producer_identity"]
    record["bound_producer_identity"] = producer["producer_identity"]
    record["producer_exit_status"] = producer["producer_exit"]
    record.update(definition.get("mutate", {}))
    record["artifacts"][0].update(definition.get("artifact_mutate", {}))
    if definition.get("outside"):
        (case_dir / "outside.txt").write_bytes(content)
    write_journal(case_dir / "journal.jsonl", record)
    write_policy(
        case_dir / "policy.json",
        None if definition.get("policy_missing") else record["record_id"],
        definition.get("policy_mutate"),
    )
    if definition.get("delete_artifact"):
        artifact.unlink()
    if definition.get("tamper_artifact"):
        artifact.write_bytes(b"TAMPERED\n")
    return producer


def compare_resolution(expected: str, document: dict[str, Any], exit_code: int) -> tuple[bool, str | None]:
    result_items = document.get("results") or []
    actual = result_items[-1].get("resolution") if result_items else None
    passed = (
        exit_code == 0
        and document.get("classification") == "RESOLUTION"
        and document.get("rule_version") == RULE_VERSION
        and actual == expected
    )
    return passed, actual


def retain_probe_process(
    case_dir: Path, pid: int, exit_code: int, stdout: str, stderr: str
) -> None:
    case_dir.mkdir(parents=True, exist_ok=True)
    (case_dir / "resolver.stdout.json").write_text(
        stdout + ("\n" if stdout else ""), encoding="utf-8"
    )
    (case_dir / "resolver.stderr.txt").write_text(
        stderr + ("\n" if stderr else ""), encoding="utf-8"
    )
    (case_dir / "resolver.exit.json").write_text(
        canonical_json({"child_pid": pid, "exit_code": exit_code}) + "\n",
        encoding="utf-8",
    )


def run_apparatus_probes(
    python: Path, run_root: Path, events: Path
) -> list[dict[str, Any]]:
    probes = []
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(SOURCE_ROOT)
    child = subprocess.Popen(
        [str(python), "-m", "evidence_resolution.cli", "self-exit", "--code", "37"],
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    stdout, stderr = child.communicate(timeout=30)
    stdout = stdout.strip()
    stderr = stderr.strip()
    exit_dir = run_root / "apparatus-nonzero-exit"
    retain_probe_process(exit_dir, child.pid, int(child.returncode), stdout, stderr)
    exit_probe = {
        "probe": "nonzero_exit_propagation",
        "expected": 37,
        "actual": child.returncode,
        "pass": child.returncode == 37,
        "child_pid": child.pid,
        "probe_dir": exit_dir.name,
    }
    probes.append(exit_probe)
    append_event(events, {"event_type": "apparatus_probe", **exit_probe})

    mismatch_document = {
        "classification": "RESOLUTION",
        "rule_version": RULE_VERSION,
        "results": [{"resolution": "REJECTED"}],
    }
    mismatch_detected = not compare_resolution("VERIFIED", mismatch_document, 0)[0]
    mismatch_dir = run_root / "apparatus-expected-mismatch"
    mismatch_dir.mkdir(parents=True)
    (mismatch_dir / "input.json").write_text(
        canonical_json({
            "expected_resolution": "VERIFIED",
            "document": mismatch_document,
            "exit_code": 0,
        }) + "\n",
        encoding="utf-8",
    )
    compare_probe = {
        "probe": "expected_mismatch_detection",
        "expected": True,
        "actual": mismatch_detected,
        "pass": mismatch_detected is True,
        "probe_dir": mismatch_dir.name,
    }
    probes.append(compare_probe)
    append_event(events, {"event_type": "apparatus_probe", **compare_probe})

    malformed_document = {"classification": "RESOLUTION", "rule_version": RULE_VERSION}
    malformed_detected = not compare_resolution("VERIFIED", malformed_document, 0)[0]
    malformed_dir = run_root / "apparatus-missing-result-schema"
    malformed_dir.mkdir(parents=True)
    (malformed_dir / "input.json").write_text(
        canonical_json({
            "expected_resolution": "VERIFIED",
            "document": malformed_document,
            "exit_code": 0,
        }) + "\n",
        encoding="utf-8",
    )
    schema_probe = {
        "probe": "missing_result_schema_detection",
        "expected": True,
        "actual": malformed_detected,
        "pass": malformed_detected is True,
        "probe_dir": malformed_dir.name,
    }
    probes.append(schema_probe)
    append_event(events, {"event_type": "apparatus_probe", **schema_probe})
    return probes


def run_corrupt_journal_probe(python: Path, run_root: Path, events: Path) -> dict[str, Any]:
    case_dir = run_root / "apparatus-corrupt-journal"
    (case_dir / "artifacts").mkdir(parents=True)
    (case_dir / "journal.jsonl").write_text("{not-json}\n", encoding="utf-8")
    write_policy(case_dir / "policy.json", None)
    pid, exit_code, stdout, stderr = launch_resolver(python, case_dir, "generation-1")
    retain_probe_process(case_dir, pid, exit_code, stdout, stderr)
    try:
        document = json.loads(stdout)
    except json.JSONDecodeError:
        document = {}
    passed = (
        exit_code == 70
        and document.get("classification") == "HARNESS_DEFECT"
        and not stderr
    )
    probe = {
        "probe": "corrupt_journal_classification",
        "expected_exit": 70,
        "actual_exit": exit_code,
        "expected_classification": "HARNESS_DEFECT",
        "actual_classification": document.get("classification"),
        "pass": passed,
        "child_pid": pid,
        "stderr": stderr,
        "probe_dir": case_dir.name,
    }
    append_event(events, {"event_type": "apparatus_probe", **probe})
    return probe


def run_hash_tamper_probe(python: Path, run_root: Path, events: Path) -> dict[str, Any]:
    case_dir = run_root / "apparatus-hash-tamper"
    (case_dir / "artifacts").mkdir(parents=True)
    payload = {"event_type": "evidence_record", "record": base_record("tamper", "0" * 64)}
    envelope = journal_envelope(payload)
    envelope["entry_hash"] = "f" * 64
    (case_dir / "journal.jsonl").write_text(canonical_json(envelope) + "\n", encoding="utf-8")
    write_policy(case_dir / "policy.json", None)
    pid, exit_code, stdout, stderr = launch_resolver(python, case_dir, "generation-1")
    retain_probe_process(case_dir, pid, exit_code, stdout, stderr)
    try:
        document = json.loads(stdout)
    except json.JSONDecodeError:
        document = {}
    passed = (
        exit_code == 70
        and document.get("classification") == "HARNESS_DEFECT"
        and document.get("error_code") == "JOURNAL_HASH"
    )
    probe = {
        "probe": "journal_hash_tamper_classification",
        "expected_exit": 70,
        "actual_exit": exit_code,
        "expected_classification": "HARNESS_DEFECT",
        "actual_classification": document.get("classification"),
        "expected_error_code": "JOURNAL_HASH",
        "actual_error_code": document.get("error_code"),
        "pass": passed,
        "child_pid": pid,
        "stderr": stderr,
        "probe_dir": case_dir.name,
    }
    append_event(events, {"event_type": "apparatus_probe", **probe})
    return probe


def run_corrupt_policy_probe(python: Path, run_root: Path, events: Path) -> dict[str, Any]:
    case_dir = run_root / "apparatus-corrupt-policy"
    (case_dir / "artifacts").mkdir(parents=True)
    write_journal(case_dir / "journal.jsonl", base_record("policy", "0" * 64))
    (case_dir / "policy.json").write_text("{broken-policy}\n", encoding="utf-8")
    pid, exit_code, stdout, stderr = launch_resolver(python, case_dir, "generation-1")
    retain_probe_process(case_dir, pid, exit_code, stdout, stderr)
    try:
        document = json.loads(stdout)
    except json.JSONDecodeError:
        document = {}
    passed = (
        exit_code == 70
        and document.get("classification") == "HARNESS_DEFECT"
        and not stderr
    )
    probe = {
        "probe": "corrupt_policy_classification",
        "expected_exit": 70,
        "actual_exit": exit_code,
        "expected_classification": "HARNESS_DEFECT",
        "actual_classification": document.get("classification"),
        "pass": passed,
        "child_pid": pid,
        "stderr": stderr,
        "probe_dir": case_dir.name,
    }
    append_event(events, {"event_type": "apparatus_probe", **probe})
    return probe


def run_nonobject_policy_probe(python: Path, run_root: Path, events: Path) -> dict[str, Any]:
    case_dir = run_root / "apparatus-nonobject-policy"
    (case_dir / "artifacts").mkdir(parents=True)
    write_journal(case_dir / "journal.jsonl", base_record("policy-shape", "0" * 64))
    (case_dir / "policy.json").write_text("[]\n", encoding="utf-8")
    pid, exit_code, stdout, stderr = launch_resolver(python, case_dir, "generation-1")
    retain_probe_process(case_dir, pid, exit_code, stdout, stderr)
    try:
        document = json.loads(stdout)
    except json.JSONDecodeError:
        document = {}
    passed = (
        exit_code == 70
        and document.get("classification") == "HARNESS_DEFECT"
        and document.get("error_code") == "EVIDENCE_SCHEMA"
        and not stderr
    )
    probe = {
        "probe": "nonobject_policy_classification",
        "expected_exit": 70,
        "actual_exit": exit_code,
        "expected_classification": "HARNESS_DEFECT",
        "actual_classification": document.get("classification"),
        "expected_error_code": "EVIDENCE_SCHEMA",
        "actual_error_code": document.get("error_code"),
        "pass": passed,
        "child_pid": pid,
        "stderr": stderr,
        "probe_dir": case_dir.name,
    }
    append_event(events, {"event_type": "apparatus_probe", **probe})
    return probe


def run_nonobject_journal_payload_probe(
    python: Path, run_root: Path, events: Path
) -> dict[str, Any]:
    case_dir = run_root / "apparatus-nonobject-journal-payload"
    (case_dir / "artifacts").mkdir(parents=True)
    envelope = journal_envelope([])  # type: ignore[arg-type]
    (case_dir / "journal.jsonl").write_text(canonical_json(envelope) + "\n", encoding="utf-8")
    write_policy(case_dir / "policy.json", None)
    pid, exit_code, stdout, stderr = launch_resolver(python, case_dir, "generation-1")
    retain_probe_process(case_dir, pid, exit_code, stdout, stderr)
    try:
        document = json.loads(stdout)
    except json.JSONDecodeError:
        document = {}
    passed = (
        exit_code == 70
        and document.get("classification") == "HARNESS_DEFECT"
        and document.get("error_code") == "JOURNAL_SCHEMA"
        and not stderr
    )
    probe = {
        "probe": "nonobject_journal_payload_classification",
        "expected_exit": 70,
        "actual_exit": exit_code,
        "expected_classification": "HARNESS_DEFECT",
        "actual_classification": document.get("classification"),
        "expected_error_code": "JOURNAL_SCHEMA",
        "actual_error_code": document.get("error_code"),
        "pass": passed,
        "child_pid": pid,
        "stderr": stderr,
        "probe_dir": case_dir.name,
    }
    append_event(events, {"event_type": "apparatus_probe", **probe})
    return probe


def build_manifest(run_root: Path) -> Path:
    manifest = run_root / "SHA256SUMS.txt"
    lines = []
    for path in sorted(item for item in run_root.rglob("*") if item.is_file() and item != manifest):
        lines.append(f"{sha256_file(path)}  {path.relative_to(run_root).as_posix()}")
    manifest.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--python", type=Path, default=Path(sys.executable))
    parser.add_argument("--run-id")
    args = parser.parse_args()
    run_id = args.run_id or datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    run_root = PROJECT_ROOT / "evidence" / "runs" / run_id
    if run_root.exists():
        raise SystemExit("refusing to overwrite an existing evidence run")
    run_root.mkdir(parents=True)
    events = run_root / "events.jsonl"
    append_event(events, {
        "event_type": "run_started",
        "run_id": run_id,
        "controller_pid": os.getpid(),
        "python": str(args.python.resolve()),
        "python_version": sys.version,
        "rule_version": RULE_VERSION,
        "repetitions": REPETITIONS,
    })

    probes = run_apparatus_probes(args.python, run_root, events)
    probes.append(run_corrupt_journal_probe(args.python, run_root, events))
    probes.append(run_hash_tamper_probe(args.python, run_root, events))
    probes.append(run_corrupt_policy_probe(args.python, run_root, events))
    probes.append(run_nonobject_policy_probe(args.python, run_root, events))
    probes.append(run_nonobject_journal_payload_probe(args.python, run_root, events))
    case_results = []
    for definition in case_definitions():
        for repetition in range(1, REPETITIONS + 1):
            case_dir = run_root / "cases" / definition["id"] / f"rep-{repetition}"
            producer = prepare_case(args.python, case_dir, definition, repetition)
            child_pid, exit_code, stdout, stderr = launch_resolver(
                args.python, case_dir, definition.get("generation", "generation-1")
            )
            (case_dir / "resolver.stdout.json").write_text(stdout + ("\n" if stdout else ""), encoding="utf-8")
            (case_dir / "resolver.stderr.txt").write_text(stderr + ("\n" if stderr else ""), encoding="utf-8")
            (case_dir / "resolver.exit.json").write_text(
                canonical_json({"child_pid": child_pid, "exit_code": exit_code}) + "\n",
                encoding="utf-8",
            )
            parse_error = None
            try:
                document = json.loads(stdout)
            except json.JSONDecodeError as exc:
                document = {}
                parse_error = str(exc)
            (
                stored_producer_document,
                stored_journal_record,
                stored_evidence_error,
            ) = load_stored_case_evidence(case_dir)
            parse_error = parse_error or stored_evidence_error
            passed, actual = compare_resolution(definition["expected"], document, exit_code)
            raw_identity = producer["producer_identity"]
            expected_record_identity = (
                "unbound-producer" if definition["id"] == "producer_mismatch" else raw_identity
            )
            journal_identity_binding_ok = (
                stored_journal_record.get("producer_identity") == expected_record_identity
                and stored_journal_record.get("bound_producer_identity") == raw_identity
            )
            raw_binding_ok = (
                stored_producer_document.get("pid") == producer["producer_pid"]
                and stored_producer_document.get("nonce")
                == producer["producer_identity"].split(";nonce:", 1)[1]
                and document.get("process_id") == child_pid
                and sha256_file(case_dir / "producer.stdout.json")
                == producer["producer_stdout_sha256"]
                and journal_identity_binding_ok
            )
            passed = passed and parse_error is None and raw_binding_ok
            result_items = document.get("results") or []
            actual_item = result_items[-1] if result_items else {}
            normalized_hash = sha256_bytes(canonical_json(normalize_result(document)).encode("utf-8"))
            result = {
                "case_id": definition["id"],
                "repetition": repetition,
                "expected_resolution": definition["expected"],
                "actual_resolution": actual,
                "actual_reason_code": actual_item.get("reason_code"),
                "checked_artifacts": actual_item.get("checked_artifacts"),
                "pass": passed,
                "child_pid": child_pid,
                "child_exit": exit_code,
                "producer_pid": producer["producer_pid"],
                "producer_exit": producer["producer_exit"],
                "producer_identity": producer["producer_identity"],
                "producer_stdout_sha256": producer["producer_stdout_sha256"],
                "raw_process_binding_ok": raw_binding_ok,
                "journal_identity_binding_ok": journal_identity_binding_ok,
                "stdout_sha256": sha256_bytes(stdout.encode("utf-8")),
                "normalized_result_sha256": normalized_hash,
                "journal_sha256": sha256_file(case_dir / "journal.jsonl"),
                "policy_sha256": sha256_file(case_dir / "policy.json"),
                "parse_error": parse_error,
                "stderr": stderr,
            }
            case_results.append(result)
            append_event(events, {"event_type": "case_completed", **result})

    grouped_hashes: dict[str, set[str]] = {}
    for result in case_results:
        grouped_hashes.setdefault(result["case_id"], set()).add(result["normalized_result_sha256"])
    determinism = {
        case_id: len(hashes) == 1 for case_id, hashes in sorted(grouped_hashes.items())
    }
    all_cases_pass = all(item["pass"] for item in case_results)
    all_probes_pass = all(item["pass"] for item in probes)
    all_deterministic = all(determinism.values())
    summary = {
        "run_id": run_id,
        "rule_version": RULE_VERSION,
        "case_definitions": len(case_definitions()),
        "repetitions_per_case": REPETITIONS,
        "case_executions": len(case_results),
        "case_passes": sum(1 for item in case_results if item["pass"]),
        "apparatus_probes": len(probes),
        "apparatus_probe_passes": sum(1 for item in probes if item["pass"]),
        "deterministic_by_case": determinism,
        "overall": "PASS" if all_cases_pass and all_probes_pass and all_deterministic else "FAIL",
        "codex_target_runs": 0,
        "martin_logic_used": False,
        "model_output_used_as_evidence": False,
    }
    (run_root / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    append_event(events, {"event_type": "run_completed", **summary})
    manifest = build_manifest(run_root)
    print(canonical_json({
        "summary": summary,
        "evidence_root": str(run_root),
        "manifest": str(manifest),
        "manifest_sha256": sha256_file(manifest),
    }))
    return 0 if summary["overall"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
