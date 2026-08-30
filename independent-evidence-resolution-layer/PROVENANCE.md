# Provenance boundary

## Comparison record only

The Martin proposal, OpenAI's implementation, PR #41567, commit
`f5636bb733c4653a6b91413fed1aaf8842374f2e`, and the earlier failed Windows
measurement attempts are retained only as provenance, comparison material, and
known-failure history.

They are not used as:

- an oracle;
- an expected-state generator;
- a data model;
- a state machine;
- a recovery or permission design;
- a naming source;
- a test-fixture source.

## Inputs to this implementation

1. The user's independent specification: model output is not evidence; missing
   evidence does not pass; process status, artifacts, hashes, identity, and
   canaries are independently observable.
2. Python 3.12 standard-library interfaces.
3. New implementation details created specifically for this reference:
   hash-chained JSONL, immutable resolution records, subprocess conformance
   cases, controller-owned verification policies, and a generated verified-facts
   view.

No third-party mitigation proposal is incorporated.

Independent provenance does not claim that every individual programming concept
is novel. It means the excluded proposal was not used to select this design's
requirements, record schema, resolution rules, or tests.
