# Validation report

## Outcome

The independent Python reference implementation and its external deterministic
controller were created and tested locally. The current accepted run is
`run-011-fifth-review-hardening`. It supersedes runs 006 through 010 for the
current source but does not erase their historical results.

Accepted-run result:

- unit tests: 25/25 passed;
- conformance definitions: 19;
- repetitions per definition: 3;
- conformance executions: 57/57 passed;
- apparatus probes: 8/8 passed;
- independent auditor: PASS, zero errors;
- manifest entries: 431, zero closure or hash errors;
- separate producer launches: 57, with 57 distinct PID-plus-nonce identities;
- distinct producer PIDs observed: 53, demonstrating actual Windows PID reuse;
- distinct resolver PIDs observed: 53;
- Codex target runs: 0;
- model output used as verifier evidence: false.

Resolution distribution:

- `VERIFIED`: 6;
- `REJECTED`: 18;
- `UNKNOWN`: 24;
- `OBSERVED`: 3;
- `STORED`: 6.

Positive and adverse cases used the same producer launcher, journal format,
resolver entry point, controller comparison function, repetition count, and raw
evidence binding checks.

## Adverse self-audit history

Earlier green summaries were not treated as final evidence.

- run 001 lacked claim-value binding and used static producer identity;
- run 002 added those checks but did not semantically inspect the canary;
- run 003 added semantic canary checks but still allowed checker selection in
  the evidence record;
- run 004 separated checker expectations into a controller-owned policy;
- run 005 attempted raw-output retention but accidentally wrote resolver output
  into every producer-output file. Its controller summary said PASS, while the
  later independent auditor correctly returned FAIL with 57 producer PID binding
  errors;
- run 006 fixed the raw-output path, added binding checks to the controller, and
  passed the then-current independent auditor with zero errors;
- after merge, automated review identified three gaps that those checks did not
  cover: journal identity fields were not independently bound to raw producer
  PID and nonce, non-object JSON policies could escape structured failure, and
  duplicate repetition IDs could satisfy a count-only audit;
- run 007 fixes all three gaps, adds direct regression tests and two new
  apparatus probes, and passes the revised independent auditor with zero errors;
- a second adversarial review then found three more gaps: malformed scalar types
  could be coerced into valid evidence, eight passing probes could omit required
  probe identities, and a malformed regular-case journal could escape the
  controller's caught error path;
- run 008 removes scalar coercion, requires every named probe exactly once, and
  converts stored-evidence shape failures into case-level non-passing results.
  It passes 19 unit tests, the full conformance matrix, and the revised auditor;
- a third adversarial review found three more gaps: Boolean journal sequences
  could equal integer sequence values in Python, the auditor parsed journal
  payloads without independently verifying the envelope hash, and apparatus
  probe events could report `pass: true` without an independent semantic
  recalculation;
- run 009 requires exact integer journal sequences, validates the journal
  envelope and canonical SHA-256 independently, and recomputes all eight probe
  verdicts from their observed and expected fields. It passes 22 unit tests,
  the full conformance matrix, and the revised auditor;
- a fourth adversarial review showed that a schema-invalid retained record, such
  as string `event_count`, could still pass after its journal and manifest hashes
  were rebuilt because the auditor inspected only identity fields;
- run 010 independently validates every required evidence-record field, exact
  integer and array types, SHA-256 fields, and artifact-reference shapes before
  using the journal payload. It passes 23 unit tests, the full conformance matrix,
  and the revised auditor;
- a fifth adversarial review showed that a schema-valid journal, policy,
  artifact, and rebuilt manifest could still retain a stale resolver verdict,
  and that controller-authored probe `actual_*` fields were not bound to raw
  probe outputs or fixtures;
- run 011 adds an independent case oracle that applies the retained policy to
  the retained artifact and compares the complete recomputed result. It also
  retains and validates every probe's fixture, stdout, stderr, exit status, and
  child identity. It passes 25 unit tests, the full conformance matrix, and the
  revised auditor.

Run 005 remains preserved with its original SHA-256 manifest. It is evidence of
an apparatus defect, not a successful validation. Runs 006 through 010 remain
valid records of what their earlier matrices observed, but none is used as
evidence that later review findings were absent.

## Accepted evidence

- `evidence/runs/run-011-fifth-review-hardening/events.jsonl`
- `evidence/runs/run-011-fifth-review-hardening/summary.json`
- `evidence/runs/run-011-fifth-review-hardening/SHA256SUMS.txt`
- per-case producer stdout/stderr, resolver stdout/stderr, journal, policy, and
  artifact files below the accepted run directory.

Accepted evidence-manifest SHA-256:

`b74622811bf45cc8b777bfc8e67637db5436292bb34a0a62650381b24318374b`

## Reproduction commands

```powershell
python -m unittest discover -s tests -v
python controller/run_conformance.py
python controller/audit_run.py evidence/runs/<generated-run-id>
```

The auditor contains its own static expected-result table and does not import the
resolver or controller case definitions. It now requires each exact
`(case_id, repetition)` coordinate once and independently reads the journal's
two identity fields, binding them to raw producer PID and nonce evidence.
It also requires all eight named apparatus probes exactly once.
For each probe, the auditor recomputes the verdict from the recorded expected
and actual values instead of trusting the controller's `pass` field. It also
validates the journal envelope, chain root, and canonical entry hash before
using its payload. CI uploads the complete generated evidence directory for each
OS and Python matrix job as a 30-day workflow artifact.
The auditor also resolves every case independently from the journal, policy,
artifact bytes, run/generation scope, process outcome, and semantic checker. It
binds each apparatus event to the retained probe fixture and raw process files.

## Boundary

PR #41567 and commit `f5636bb733c4653a6b91413fed1aaf8842374f2e` are
provenance/comparison records only. They were not run, modified, or used as the
resolver's oracle, schema, state machine, or test input.
