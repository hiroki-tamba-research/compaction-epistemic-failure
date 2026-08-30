# Comparison boundary

## What PR #41567 addresses

OpenAI Codex PR #41567 / commit
`f5636bb733c4653a6b91413fed1aaf8842374f2e` restores thread cwd from an owned
`ThreadSettingsApplied` snapshot and checkpoints current settings around
compaction. That implementation is a comparison record, not an implementation
input to IERL.

## What IERL addresses

IERL asks a different and broader evidence question: which observations may be
represented to a later agent context as independently verified facts?

IERL-1 requires:

- an intact sequential hash-chained journal;
- matching run and generation scope;
- independently bound producer identity;
- complete event ordering;
- a successful process exit;
- present and readable artifacts;
- matching artifact and claim hashes;
- a controller-owned verification policy;
- a passing deterministic semantic checker.

Missing evidence becomes `UNKNOWN`; contradictory evidence becomes `REJECTED`;
model text alone remains `OBSERVED`.

## Claims that are supported

- The Python reference passes its declared local matrix.
- Positive and adverse cases use the same resolution path.
- A separate auditor with a static expected table detects a known false-green
  controller run.
- The design does not depend on model self-report.

## Claims that are not supported

- IERL has not been integrated into Codex.
- No Codex compaction, resume, cwd, hosted-runtime, or cold-restart experiment
  was run by this implementation.
- The results do not falsify or validate PR #41567.
- “Stronger” applies only to the explicitly tested evidence-integrity
  properties, not to all functionality, performance, or compatibility.

