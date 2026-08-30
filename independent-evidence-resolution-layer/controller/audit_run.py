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


def audit(run_root: Path) -> dict[str, Any]:
    errors: list[str] = []
    try:
        summary = load_json(run_root / "summary.json")
        events = [json.loads(line) for line in (run_root / "events.jsonl").read_text(encoding="utf-8").splitlines()]
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return {"overall": "FAIL", "errors": [f"run_parse:{exc}"]}
    cases = [event for event in events if event.get("event_type") == "case_completed"]
    probes = [event for event in events if event.get("event_type") == "apparatus_probe"]
    seen: Counter[str] = Counter()
    distribution: Counter[str] = Counter()
    for case in cases:
        case_id = str(case.get("case_id"))
        repetition = case.get("repetition")
        seen[case_id] += 1
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
            results = resolver.get("results") or []
            raw_actual = results[-1].get("resolution") if results else None
            if producer.get("pid") != case.get("producer_pid"):
                errors.append(f"{label}:producer_pid_binding")
            if resolver.get("process_id") != case.get("child_pid"):
                errors.append(f"{label}:resolver_pid_binding")
            if raw_actual != actual:
                errors.append(f"{label}:raw_resolution_binding")
            if sha256_file(case_dir / "journal.jsonl") != case.get("journal_sha256"):
                errors.append(f"{label}:journal_hash")
            if sha256_file(case_dir / "policy.json") != case.get("policy_sha256"):
                errors.append(f"{label}:policy_hash")
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            errors.append(f"{label}:raw_evidence:{exc}")

    for case_id in sorted(EXPECTED):
        if seen[case_id] != 3:
            errors.append(f"{case_id}:repetition_count:{seen[case_id]}")
    if len(cases) != 57:
        errors.append(f"case_count:{len(cases)}")
    if len(probes) != 6 or any(probe.get("pass") is not True for probe in probes):
        errors.append("apparatus_probes")
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

