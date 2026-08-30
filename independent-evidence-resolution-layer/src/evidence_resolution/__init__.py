"""Independent Evidence Resolution Layer reference implementation."""

from .model import ArtifactRef, EvidenceRecord, ResolutionResult, VerificationRule
from .resolver import RULE_VERSION, resolve_record
from .store import JournalError, JsonlJournal

__all__ = [
    "ArtifactRef",
    "EvidenceRecord",
    "JournalError",
    "JsonlJournal",
    "ResolutionResult",
    "VerificationRule",
    "RULE_VERSION",
    "resolve_record",
]
