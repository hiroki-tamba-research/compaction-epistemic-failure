# Validation report

## Outcome

The independent Python reference implementation and its external deterministic
controller were created and tested locally. The accepted run is
`20260830T-IERL-V1-006`.

Accepted-run result:

- unit tests: 12/12 passed;
- conformance definitions: 19;
- repetitions per definition: 3;
- conformance executions: 57/57 passed;
- apparatus probes: 6/6 passed;
- independent auditor: PASS, zero errors;
- manifest entries: 407, zero closure or hash errors;
- distinct synthetic producer processes: 57;
- distinct resolver processes: 57;
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
  passed the independent auditor with zero errors.

Run 005 remains preserved with its original SHA-256 manifest. It is evidence of
an apparatus defect, not a successful validation.

## Accepted evidence

- `evidence/runs/20260830T-IERL-V1-006/events.jsonl`
- `evidence/runs/20260830T-IERL-V1-006/summary.json`
- `evidence/runs/20260830T-IERL-V1-006/SHA256SUMS.txt`
- per-case producer stdout/stderr, resolver stdout/stderr, journal, policy, and
  artifact files below the accepted run directory.

Accepted evidence-manifest SHA-256:

`0e49584f4befa5addc3cffa5a1e8766cedd50a631929c070626003817df80251`

## Reproduction commands

```powershell
python -m unittest discover -s tests -v
python controller/run_conformance.py
python controller/audit_run.py evidence/runs/<generated-run-id>
```

The auditor contains its own static expected-result table and does not import the
resolver or controller case definitions.

## Boundary

PR #41567 and commit `f5636bb733c4653a6b91413fed1aaf8842374f2e` are
provenance/comparison records only. They were not run, modified, or used as the
resolver's oracle, schema, state machine, or test input.
