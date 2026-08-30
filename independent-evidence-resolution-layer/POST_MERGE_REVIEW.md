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

## Second adversarial review

The first hardening commit was not merged immediately. A fresh automated review
completed at `2026-08-30T03:31:06Z` and reported another P1 plus two P2 findings.

### P1: malformed scalar types were coerced into valid evidence

Numeric identities, Boolean exit status, fractional event counts, and string
sequence values could be normalized by `str()` and `int()` and reach
`VERIFIED`. Model construction now performs exact JSON type checks. Boolean is
not accepted as an integer, hashes must be 64 hexadecimal characters, sequence
members must be integers, and policy arrays contain only their declared types.

Regression test:
`CliSchemaTests.test_malformed_field_types_emit_structured_harness_defect`.

### P2: required apparatus probes were count-only

Eight arbitrary passing probe events could satisfy the auditor. The auditor now
owns an independent set of eight expected probe names and requires every name
exactly once.

Regression test:
`AuditorRegressionTests.test_duplicate_probes_cannot_replace_required_probes`.

### P2: regular-case journal shape errors escaped controller handling

The controller's journal parser raised an exception type that its caller did not
catch. Stored case evidence now goes through one fail-closed loader that converts
object-shape, JSON, type, and I/O failures into a case-level `parse_error` and a
non-passing controller result.

Regression test:
`AuditorRegressionTests.test_controller_captures_nonobject_case_journal`.

## Third adversarial review

The second hardening commit was also held open for a fresh automated review.
That review completed at `2026-08-30T03:43:11Z` and reported another P1, a
second P1, and one P2 finding.

### P1: Boolean journal sequence was accepted as integer sequence 1

Python equality makes `True == 1`. The journal loader now requires the exact
integer type before comparing the sequence value. Hash fields are also required
to be lowercase 64-character SHA-256 strings before chain or entry comparison.

Regression test:
`JournalTests.test_boolean_sequence_is_apparatus_defect`.

### P1: auditor trusted the journal payload without validating its envelope hash

The independent auditor now requires one complete journal envelope, exact
sequence 1, the all-zero chain root, a lowercase SHA-256 entry hash, and a match
against its own canonical JSON SHA-256 calculation before it reads the payload.

Regression test:
`AuditorRegressionTests.test_auditor_recomputes_journal_entry_hash`.

### P2: auditor trusted the controller's apparatus `pass` field

The auditor now independently recomputes every apparatus verdict from its
recorded expected and actual exit statuses, classifications, error codes,
detection flags, and stderr. A forged `pass: true` cannot replace the underlying
probe evidence.

Regression test:
`AuditorRegressionTests.test_false_probe_pass_flag_is_independently_rejected`.

## Revised validation

Accepted run: `run-009-third-review-hardening`.

- unit tests: 22/22;
- conformance executions: 57/57;
- apparatus probes: 8/8;
- revised independent auditor: PASS, zero errors;
- evidence manifest entries: 411;
- evidence manifest SHA-256:
  `2cbac59be4d11173bb917039dc4a771c7a0491ef64c0cfde145531758ef6dec8`;
- Codex target runs: 0;
- model output used as evidence: false.

This hardening does not establish correctness outside the tested matrix. It also
does not turn IERL into a Codex patch or a reproduction of PR #41567.
