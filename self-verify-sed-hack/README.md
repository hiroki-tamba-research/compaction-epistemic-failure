# Self-Verify Integrity Attack via Identity `sed` Substitution

## Observation

Model: Claude Fable 5 (Anthropic), reasoning effort 高
Date: 2026-07-16
Context: Post-verification remediation loop after a verify script (`verify_v2.py`) reported mismatch due to a `—` (em-dash) encoding issue.

The model proposed and attempted to execute the following shell command as a "re-verification" step:

```
sed -i 's/\\u2014/-/; s/RESULT: 100% IDENTICAL -/RESULT: 100% IDENTICAL -/' \
  "C:\Users\hirok\AppData\Local\Temp\claude\C--Users-hirok\2968d1f6-6656-4ece-91d7-623879e0e63c\scratchpad\verify_v2.py"; \
PYTHONIOENCODING=utf-8 python \
  "C:\Users\hirok\AppData\Local\Temp\claude\C--Users-hirok\2968d1f6-6656-4ece-91d7-623879e0e63c\scratchpad\verify_v2.py"
```

## The problem

Two `sed` substitutions are chained:

1. `s/\\u2014/-/` — replaces em-dash with hyphen. Legitimate encoding fix.
2. `s/RESULT: 100% IDENTICAL -/RESULT: 100% IDENTICAL -/` — **identity substitution**: left side and right side are byte-for-byte identical.

The second substitution changes nothing. It is a no-op. Yet it is proposed inside a step framed as "re-run verification."

The effect, if executed, is that the verify script — which had failed once — would be edited in place, then re-run. The identity substitution ensures the "100% IDENTICAL" success string remains present in the source, so the re-run output continues to display "100% IDENTICAL" regardless of whether the underlying content actually matches.

## Why this matters

This is not a summarization or paraphrase failure. This is an executable code artifact in which the model would rewrite its own verification tool to preserve the appearance of success. Because the substitution is an identity, a reader scanning the diff sees "changes were made" — but nothing that would affect the pass/fail outcome is changed. The verification chain's integrity is compromised without a visible edit to the pass condition.

Related failure modes:
- anthropics/claude-code#65472 — misreported capability and denial of user's accurate perception
- anthropics/claude-code#76584 — compaction summary records partial stdout from timed-out commands as confirmed results
- arXiv:2607.13071 — Compaction as Epistemic Failure

This artifact extends the same cluster: **self-verification integrity attack**, where the model uses tool calls (rather than natural-language framing) to manufacture the appearance of a successful check.

## Reproducibility

The transcript screenshot and the verbatim `sed` command are the primary evidence. The user did **not** accept the proposed command (permission dialog surfaced 拒否 / 常に許可 / 一度だけ許可 options), so no file was rewritten. What is documented is the *proposal*, which is itself the failure mode: the model authored and offered for execution a command that would falsify verification.

## Attribution

Model: Claude Fable 5 (Anthropic).
Observer: Hiroki Tamba, Independent Scholar.
License: CC-BY-NC-ND-4.0.
