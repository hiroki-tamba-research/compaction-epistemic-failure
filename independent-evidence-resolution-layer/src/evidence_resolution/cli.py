from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from .model import EvidenceRecord, VerificationRule
from .resolver import RULE_VERSION, resolve_record
from .store import JournalError, JsonlJournal


def _emit(value: dict[str, object]) -> None:
    print(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")))


def resolve_command(args: argparse.Namespace) -> int:
    try:
        policy_bytes = Path(args.policy).read_bytes()
        policy = json.loads(policy_bytes)
        if not isinstance(policy, dict):
            raise ValueError("verification policy must be a JSON object")
        if policy.get("policy_version") != "IERL-POLICY-1" or not isinstance(policy.get("rules"), dict):
            raise ValueError("invalid verification policy")
        entries = JsonlJournal(Path(args.journal)).load()
        results = []
        for envelope in entries:
            payload = envelope["payload"]
            if payload.get("event_type") != "evidence_record":
                continue
            record = EvidenceRecord.from_dict(payload["record"])
            raw_rule = policy["rules"].get(record.record_id)
            rule = None if raw_rule is None else VerificationRule.from_dict(raw_rule)
            result = resolve_record(
                record,
                Path(args.artifact_root),
                args.run_id,
                args.generation_id,
                rule,
            )
            results.append(result.to_dict())
        if not results:
            _emit({
                "classification": "HARNESS_DEFECT",
                "error_code": "NO_EVIDENCE_RECORDS",
                "process_id": os.getpid(),
                "rule_version": RULE_VERSION,
            })
            return 70
        _emit({
            "classification": "RESOLUTION",
            "process_id": os.getpid(),
            "results": results,
            "rule_version": RULE_VERSION,
        })
        return 0
    except (JournalError, ValueError, KeyError, TypeError, OSError) as exc:
        _emit({
            "classification": "HARNESS_DEFECT",
            "error_code": getattr(exc, "code", "EVIDENCE_SCHEMA"),
            "process_id": os.getpid(),
            "rule_version": RULE_VERSION,
        })
        return 70


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    resolve = subparsers.add_parser("resolve")
    resolve.add_argument("--journal", required=True)
    resolve.add_argument("--artifact-root", required=True)
    resolve.add_argument("--policy", required=True)
    resolve.add_argument("--run-id", required=True)
    resolve.add_argument("--generation-id", required=True)
    resolve.set_defaults(function=resolve_command)
    exit_parser = subparsers.add_parser("self-exit")
    exit_parser.add_argument("--code", required=True, type=int)
    exit_parser.set_defaults(function=lambda args: args.code)
    args = parser.parse_args(argv)
    return int(args.function(args))


if __name__ == "__main__":
    sys.exit(main())
