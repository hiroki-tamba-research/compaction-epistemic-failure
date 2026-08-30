# Post-merge review and hardening

## Timeline

- PR #1 merged at `2026-08-30T03:04:10Z` as
  `321d686bc6010750c38cc70d953fde38da1def9d`.
- The automated Codex review was submitted at `2026-08-30T03:07:41Z`.
- Three findings were recorded immediately after merge: one P1 and two P2.

The original twelve checks and merge state are not treated as proof that the
implementation was correct. They establish only that the original matrix was
green before the later review exposed coverage gaps.

## Findings and repairs

### P1: journal producer identity was not independently bound

The old auditor compared raw producer PID with the controller event but did not
parse the evidence journal and bind both identity fields to the raw producer PID
and nonce. Two equally wrong journal fields could therefore agree with each
other and pass.

The revised auditor reads the journal record independently. For ordinary cases,
both identity fields must equal `pid:<raw-pid>;nonce:<raw-nonce>`. The deliberate
`producer_mismatch` negative fixture is separately constrained: only its
unbound field may differ, while its bound identity must still match raw output.
The controller now performs the same binding check, while the auditor remains an
independent second calculation.

Regression test:
`AuditorRegressionTests.test_both_wrong_journal_identities_are_detected`.

### P2: syntactically valid non-object JSON escaped structured failure

A policy containing `[]` reached `.get` and could terminate with an unstructured
traceback and exit status 1. Journal payload containers had the same class of
shape risk.

The CLI, model constructors, and journal loader now require JSON objects at each
object boundary. A non-object policy produces `HARNESS_DEFECT` and exit status
70. A non-object journal payload produces `HARNESS_DEFECT`, error code
`JOURNAL_SCHEMA`, and exit status 70. Neither emits a traceback.

Regression tests and probes:

- `CliSchemaTests.test_non_object_policy_emits_structured_harness_defect`;
- `JournalTests.test_non_object_payload_is_apparatus_defect`;
- `nonobject_policy_classification` apparatus probe;
- `nonobject_journal_payload_classification` apparatus probe.

### P2: repetition counting did not require distinct coordinates

The old auditor counted only by `case_id`. Three copies of repetition 1 could
satisfy the count while repetitions 2 and 3 were absent.

The revised auditor requires every exact `(case_id, repetition)` coordinate for
repetitions 1, 2, and 3 exactly once. Invalid, missing, and duplicate coordinates
are failures before the case directory is read.

Regression test:
`AuditorRegressionTests.test_duplicate_repetition_ids_are_detected`.

## Revised validation

Accepted run: `run-007-postmerge-hardening`.

- unit tests: 16/16;
- conformance executions: 57/57;
- apparatus probes: 8/8;
- revised independent auditor: PASS, zero errors;
- evidence manifest entries: 411;
- evidence manifest SHA-256:
  `6398785db32b5ddc4da80814d852b30ad8b59d94c1c6b9ba476d71139678ad5d`;
- Codex target runs: 0;
- model output used as evidence: false.

This hardening does not establish correctness outside the tested matrix. It also
does not turn IERL into a Codex patch or a reproduction of PR #41567.
