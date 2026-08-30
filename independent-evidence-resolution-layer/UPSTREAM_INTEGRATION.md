# Upstream integration contract

This reference is intentionally outside the Codex source tree. A future upstream
port can implement the following Rust-shaped interfaces without importing any
code or behavior from PR #41567:

```rust
trait EvidenceStore {
    fn append(&self, record: EvidenceRecord) -> Result<RecordId, StoreError>;
    fn read_all(&self) -> Result<Vec<EvidenceRecord>, StoreError>;
}

trait ArtifactChecker {
    fn check(&self, artifact: &ArtifactRef) -> CheckResult;
}

trait EvidenceResolver {
    fn resolve(&self, record: &EvidenceRecord, scope: &RunScope)
        -> ResolutionRecord;
}

trait EvidenceViewBuilder {
    fn build(&self, records: &[ResolutionRecord]) -> EvidenceView;
}
```

Integration points are defined by behavior, not guessed file names:

1. Register raw tool/process completion and artifact references after the OS
   process outcome is known.
2. Append evidence before a resumable context is finalized.
3. Rebuild the evidence view from the journal when constructing any later
   context.
4. Keep generated summaries outside the verified-facts collection.

The exact crate and module paths remain unresolved until a separately authorized
read-only upstream mapping. This prototype does not modify or run Codex.

