from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


def _require_string(value: Any, field_name: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a string")
    return value


def _require_sha256(value: Any, field_name: str) -> str:
    text = _require_string(value, field_name)
    if len(text) != 64 or any(character not in "0123456789abcdefABCDEF" for character in text):
        raise ValueError(f"{field_name} must be a SHA-256 hex digest")
    return text.lower()


@dataclass(frozen=True)
class ArtifactRef:
    relative_path: str
    sha256: str

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "ArtifactRef":
        if not isinstance(value, dict):
            raise ValueError("artifact reference must be a JSON object")
        return cls(
            relative_path=_require_string(value["relative_path"], "relative_path"),
            sha256=_require_sha256(value["sha256"], "sha256"),
        )


@dataclass(frozen=True)
class VerificationRule:
    record_id: str
    checker: str
    required_keys: tuple[str, ...] = ()
    expected_text: str | None = None

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "VerificationRule":
        if not isinstance(value, dict):
            raise ValueError("verification rule must be a JSON object")
        required_keys = value.get("required_keys", [])
        if not isinstance(required_keys, list) or any(
            not isinstance(item, str) for item in required_keys
        ):
            raise ValueError("required_keys must be an array of strings")
        expected_text = value.get("expected_text")
        if expected_text is not None and not isinstance(expected_text, str):
            raise ValueError("expected_text must be a string or null")
        return cls(
            record_id=_require_string(value["record_id"], "record_id"),
            checker=_require_string(value["checker"], "checker"),
            required_keys=tuple(required_keys),
            expected_text=expected_text,
        )


@dataclass(frozen=True)
class EvidenceRecord:
    record_id: str
    run_id: str
    generation_id: str
    subject: str
    predicate: str
    value_hash: str
    producer_identity: str
    bound_producer_identity: str
    producer_exit_status: int | None
    source_kind: str
    event_count: int
    event_sequence: tuple[int, ...]
    rule_version: str
    artifacts: tuple[ArtifactRef, ...] = field(default_factory=tuple)

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "EvidenceRecord":
        if not isinstance(value, dict):
            raise ValueError("evidence record must be a JSON object")
        required = {
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
        }
        missing = sorted(required.difference(value))
        if missing:
            raise ValueError(f"missing evidence fields: {','.join(missing)}")
        exit_status = value["producer_exit_status"]
        if exit_status is not None and type(exit_status) is not int:
            raise ValueError("producer_exit_status must be an integer or null")
        event_count = value["event_count"]
        if type(event_count) is not int:
            raise ValueError("event_count must be an integer")
        event_sequence = value["event_sequence"]
        if not isinstance(event_sequence, list) or any(
            type(item) is not int for item in event_sequence
        ):
            raise ValueError("event_sequence must be an array of integers")
        artifacts = value["artifacts"]
        if not isinstance(artifacts, list):
            raise ValueError("artifacts must be an array")
        return cls(
            record_id=_require_string(value["record_id"], "record_id"),
            run_id=_require_string(value["run_id"], "run_id"),
            generation_id=_require_string(value["generation_id"], "generation_id"),
            subject=_require_string(value["subject"], "subject"),
            predicate=_require_string(value["predicate"], "predicate"),
            value_hash=_require_sha256(value["value_hash"], "value_hash"),
            producer_identity=_require_string(value["producer_identity"], "producer_identity"),
            bound_producer_identity=_require_string(
                value["bound_producer_identity"], "bound_producer_identity"
            ),
            producer_exit_status=exit_status,
            source_kind=_require_string(value["source_kind"], "source_kind"),
            event_count=event_count,
            event_sequence=tuple(event_sequence),
            rule_version=_require_string(value["rule_version"], "rule_version"),
            artifacts=tuple(ArtifactRef.from_dict(item) for item in artifacts),
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ResolutionResult:
    record_id: str
    resolution: str
    reason_code: str
    rule_version: str
    checked_artifacts: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
