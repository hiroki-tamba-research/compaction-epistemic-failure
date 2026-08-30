# Validation report

## Outcome

The independent Python reference implementation and its external deterministic
controller were created and tested locally. The current accepted run is
`run-007-postmerge-hardening`. It supersedes run 006 for the current source but
does not erase run 006's historical result.

Accepted-run result:

- unit tests: 16/16 passed;
- conformance definitions: 19;
- repetitions per definition: 3;
- conformance executions: 57/57 passed;
- apparatus probes: 8/8 passed;
- independent auditor: PASS, zero errors;
- manifest entries: 411, zero closure or hash errors;
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
  apparatus probes, and passes the revised independent auditor with zero errors.

Run 005 remains preserved with its original SHA-256 manifest. It is evidence of
an apparatus defect, not a successful validation. Run 006 remains a valid record
of what the earlier test matrix observed, but it is not used as evidence that
the post-merge review findings were absent.

## Accepted evidence

- `evidence/runs/run-007-postmerge-hardening/events.jsonl`
- `evidence/runs/run-007-postmerge-hardening/summary.json`
- `evidence/runs/run-007-postmerge-hardening/SHA256SUMS.txt`
- per-case producer stdout/stderr, resolver stdout/stderr, journal, policy, and
  artifact files below the accepted run directory.

Accepted evidence-manifest SHA-256:

`6398785db32b5ddc4da80814d852b30ad8b59d94c1c6b9ba476d71139678ad5d`

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

## Boundary

PR #41567 and commit `f5636bb733c4653a6b91413fed1aaf8842374f2e` are
provenance/comparison records only. They were not run, modified, or used as the
resolver's oracle, schema, state machine, or test input.
