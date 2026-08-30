from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class ArtifactRef:
    relative_path: str
    sha256: str

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "ArtifactRef":
        if not isinstance(value, dict):
            raise ValueError("artifact reference must be a JSON object")
        return cls(
            relative_path=str(value["relative_path"]),
            sha256=str(value["sha256"]).lower(),
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
        return cls(
            record_id=str(value["record_id"]),
            checker=str(value["checker"]),
            required_keys=tuple(str(item) for item in value.get("required_keys", [])),
            expected_text=(
                None if value.get("expected_text") is None else str(value["expected_text"])
            ),
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
        return cls(
            record_id=str(value["record_id"]),
            run_id=str(value["run_id"]),
            generation_id=str(value["generation_id"]),
            subject=str(value["subject"]),
            predicate=str(value["predicate"]),
            value_hash=str(value["value_hash"]).lower(),
            producer_identity=str(value["producer_identity"]),
            bound_producer_identity=str(value["bound_producer_identity"]),
            producer_exit_status=None if exit_status is None else int(exit_status),
            source_kind=str(value["source_kind"]),
            event_count=int(value["event_count"]),
            event_sequence=tuple(int(item) for item in value["event_sequence"]),
            rule_version=str(value["rule_version"]),
            artifacts=tuple(ArtifactRef.from_dict(item) for item in value["artifacts"]),
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
