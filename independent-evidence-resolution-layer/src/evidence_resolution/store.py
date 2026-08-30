from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any


class JournalError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


class JsonlJournal:
    def __init__(self, path: Path):
        self.path = Path(path)

    def load(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        entries: list[dict[str, Any]] = []
        previous = "0" * 64
        try:
            lines = self.path.read_text(encoding="utf-8").splitlines()
        except OSError as exc:
            raise JournalError("JOURNAL_READ", str(exc)) from exc
        for expected_sequence, line in enumerate(lines, start=1):
            try:
                envelope = json.loads(line)
            except json.JSONDecodeError as exc:
                raise JournalError("JOURNAL_PARSE", str(exc)) from exc
            required = {"sequence", "previous_hash", "payload", "entry_hash"}
            if not isinstance(envelope, dict) or not required.issubset(envelope):
                raise JournalError("JOURNAL_SCHEMA", "invalid envelope")
            if not isinstance(envelope["payload"], dict):
                raise JournalError("JOURNAL_SCHEMA", "payload must be a JSON object")
            if envelope["sequence"] != expected_sequence:
                raise JournalError("JOURNAL_SEQUENCE", "non-contiguous sequence")
            if envelope["previous_hash"] != previous:
                raise JournalError("JOURNAL_CHAIN", "previous hash mismatch")
            unsigned = {
                "sequence": envelope["sequence"],
                "previous_hash": envelope["previous_hash"],
                "payload": envelope["payload"],
            }
            calculated = sha256_bytes(canonical_json(unsigned))
            if envelope["entry_hash"] != calculated:
                raise JournalError("JOURNAL_HASH", "entry hash mismatch")
            previous = calculated
            entries.append(envelope)
        return entries

    def append(self, payload: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(payload, dict):
            raise JournalError("JOURNAL_SCHEMA", "payload must be a JSON object")
        entries = self.load()
        previous = entries[-1]["entry_hash"] if entries else "0" * 64
        unsigned = {
            "sequence": len(entries) + 1,
            "previous_hash": previous,
            "payload": payload,
        }
        envelope = dict(unsigned)
        envelope["entry_hash"] = sha256_bytes(canonical_json(unsigned))
        entries.append(envelope)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_name(f".{self.path.name}.{os.getpid()}.tmp")
        data = b"".join(canonical_json(item) + b"\n" for item in entries)
        try:
            with temporary.open("wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.path)
        finally:
            if temporary.exists():
                temporary.unlink()
        read_back = self.load()
        if not read_back or read_back[-1]["entry_hash"] != envelope["entry_hash"]:
            raise JournalError("JOURNAL_READBACK", "append read-back failed")
        return envelope
