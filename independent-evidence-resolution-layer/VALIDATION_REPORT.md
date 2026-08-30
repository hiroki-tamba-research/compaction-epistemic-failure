# Validation report

## Outcome

The independent Python reference implementation and its external deterministic
controller were created and tested locally. The current accepted run is
`run-014-seventh-review-hardening-fixed`. It supersedes runs 006 through 012 for
the current source. Run 013 is a rejected apparatus run and is not accepted.

Accepted-run result:

- unit tests: 30/30 passed;
- conformance definitions: 19;
- repetitions per definition: 3;
- conformance executions: 57/57 passed;
- apparatus probes: 8/8 passed;
- independent auditor: PASS, zero errors;
- manifest entries: 545, zero closure or hash errors;
- separate producer launches: 57, with 57 distinct PID-plus-nonce identities;
- distinct producer PIDs observed: 57;
- distinct resolver PIDs observed: 57;
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
  revised auditor;
- a sixth adversarial review showed that distinct case names could be backed by
  substituted inputs yielding the same resolution, probe stdout PID was not
  bound to the exit record, and the missing-result probe accepted any mismatch;
- run 012 binds all 19 case names to their defining record, policy, artifact,
  and generation conditions; binds resolver probe stdout PID to the retained
  child PID; and validates comparison-probe fixture shape per probe name. It
  passes 27 unit tests, the full matrix, and the revised auditor;
- a seventh adversarial review found that repetitions could reuse one producer
  identity, expected-mismatch fixture inputs were not fully pinned, regular-case
  exit/stderr were not independently retained, and resolver stdout envelopes
  were only partially checked;
- run 013 added raw producer/resolver exit records but incorrectly required the
  intentionally missing journal exit status to equal the real producer exit in
  the `missing_exit` case. The auditor rejected three cases, so run 013 is sealed
  as `HARNESS_DEFECT` rather than repaired in place;
- run 014 scopes raw producer exit binding to the event while leaving the
  intentional journal mutation to the named fixture contract. It passes 30 unit
  tests, the full matrix, and the revised auditor.

Run 005 remains preserved with its original SHA-256 manifest. It is evidence of
an apparatus defect, not a successful validation. Runs 006 through 012 remain
valid records of what their earlier matrices observed, but none is used as
evidence that later review findings were absent.

## Accepted evidence

- `evidence/runs/run-014-seventh-review-hardening-fixed/events.jsonl`
- `evidence/runs/run-014-seventh-review-hardening-fixed/summary.json`
- `evidence/runs/run-014-seventh-review-hardening-fixed/SHA256SUMS.txt`
- per-case producer stdout/stderr/exit, resolver stdout/stderr/exit, journal,
  policy, and artifact files below the accepted run directory.

Accepted evidence-manifest SHA-256:

`50d3b6ae2efb46e418dd188ba6ff5d75e9d18272dad7b1aeb1b068cb81380ba1`

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
