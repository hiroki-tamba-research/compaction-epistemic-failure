# Independent Evidence Resolution Layer (IERL) v1.6

This is a clean-room reference implementation of a deterministic evidence
resolver for long-running agent sessions. It prevents model-authored text,
partial output, missing artifacts, failed processes, and damaged journals from
being silently promoted to verified facts.

It is not an OpenAI project, not a Codex compaction harness, and not a claim that
Codex PR #41567 is incorrect. PR #41567 is retained only as comparison/provenance
history and was not used as a design input.

The resolver separates observations from independently verified facts. A model
response cannot promote a claim. Only process status, bound process identity,
artifact presence, SHA-256, deterministic checks, event completeness, and
journal integrity are used. Checker expectations are supplied in a separate
controller-owned policy, never by the evidence producer.

## Run

Use Python 3.11 or newer. The implementation has no third-party runtime
dependencies.

```powershell
python -m unittest discover -s tests -v
python controller/run_conformance.py
python controller/audit_run.py evidence/runs/<generated-run-id>
```

The controller launches the resolver as a separate process for every case and
compares its JSON result with a static expected result. Positive and adverse
fixtures use the same code path and are each repeated three times.

Evidence is written below `evidence/runs/<run-id>/`. The run directory contains
the controller event stream, per-case journals and artifacts, a summary, and a
SHA-256 manifest.

## Verdict vocabulary

- `OBSERVED`: appeared as model text or an uncorroborated observation.
- `STORED`: durably recorded and read back, but not independently checked.
- `VERIFIED`: every deterministic requirement passed.
- `REJECTED`: affirmative contradictory evidence exists.
- `UNKNOWN`: required evidence is missing or cannot be ordered/scoped.
- `HARNESS_DEFECT`: the measurement apparatus itself is malformed.

`UNKNOWN` and `HARNESS_DEFECT` are never converted to success.

## Validation result

The accepted sixth-review-hardening Windows run used 19 positive and adverse
definitions, three subprocess repetitions each: 57/57 case executions passed,
eight of eight apparatus probes passed, and the separate auditor reported zero
errors. The unit suite passed 27/27 tests.

The auditor also rejected an earlier controller-green run after detecting 57
producer PID binding failures. After v1 was merged, automated review found three
additional defects in journal identity binding, non-object input handling, and
repetition-coordinate validation. A second adversarial review then found strict
field-type, apparatus-probe identity, and controller error-capture gaps. v1.2
fixed those gaps. A third adversarial review found Boolean journal-sequence,
journal-chain-audit, and apparatus-verdict-recalculation gaps. v1.3 fixes all
nine review findings. A fourth adversarial review found that the auditor still
did not validate the complete retained evidence-record schema. v1.4 fixes all
ten review findings. A fifth adversarial review showed that case verdicts and
probe outcomes were still not recomputed from retained inputs. v1.5 fixes all
twelve review findings: the auditor now applies an independent case oracle and
binds every probe verdict to its retained fixture, stdout, stderr, exit status,
and process identity. The original green and merged states remain documented
rather than being treated as proof of correctness. A sixth adversarial review
then found case-name substitution, unbound probe stdout PID, and a generic schema
probe fixture. v1.6 fixes all fifteen review findings by binding every named case
and probe to its distinct retained condition.

See [VALIDATION_REPORT.md](VALIDATION_REPORT.md) and
[POST_MERGE_REVIEW.md](POST_MERGE_REVIEW.md) for the exact review-to-fix trace.
See [KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md) for unresolved work. CI repeats the same matrix on
Windows, Linux, and macOS; a green workflow is required before cross-platform
support can be claimed. Every CI matrix job retains its full evidence directory
as a downloadable workflow artifact for 30 days.

## Security and comparison boundary

IERL provides stronger evidence-status semantics than a plain summary or
state-snapshot restoration mechanism: process identity, exit status, artifact
hashes, semantic canaries, policy separation, journal integrity, and missing
evidence all participate in the verdict.

It is not yet integrated into Codex and has not been shown to improve or regress
Codex cwd restoration. See [COMPARISON.md](COMPARISON.md) for the exact boundary.
