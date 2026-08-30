# Known limitations and unresolved work

This reference implementation is not a production Codex patch.

- It has not been integrated into or executed against Codex.
- IERL-1 supports one artifact per claim. Multi-artifact aggregate hashing is
  unresolved and returns `UNKNOWN`.
- The JSONL writer has no multi-process locking. Concurrent append behavior is
  not validated.
- The synthetic process identity is PID plus controller nonce. A production
  Windows port should bind an OS process handle and creation identity; PID alone
  is insufficient.
- Verification-policy distribution, access control, version migration, and
  authenticity are not implemented. The controller records the policy hash, but
  this is not a signature system.
- Only `contains_utf8` and `json_object_keys` perform semantic checks. More
  predicates require separately specified deterministic checkers.
- `hash_only` and `none` can produce only `STORED`, never `VERIFIED`.
- Crash consistency has not been fault-injected at every `fsync`/`os.replace`
  boundary.
- The accepted evidence run was produced on the local Windows host. GitHub CI
  also runs the same unit, conformance, and audit commands on Windows, Ubuntu,
  and macOS with Python 3.11 and 3.12; CI does not replace production testing.
- Confidentiality, encryption, retention, deletion, and quota management are
  outside v1.
- The evidence view does not grant permissions or prevent arbitrary actions. It
  only prevents unresolved material from being labeled as verified facts by this
  component.
- Six automated review rounds found fifteen defects that earlier green checks did
  not cover. Those findings are fixed and regression-tested, but there is still
  no formal proof, independent human review, fuzzing, or production load test.

Passing run 012 means only that no mismatch was observed in the specified 19
cases, three repetitions each, plus eight apparatus probes and the revised
independent auditor. It does not establish correctness outside that matrix.
