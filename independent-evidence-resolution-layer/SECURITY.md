# Security policy

This repository is a research reference implementation. It is not deployed as a
service and does not accept secrets or production evidence.

Please report implementation vulnerabilities privately to the repository owner
before publishing exploit details. Findings about OpenAI or Codex should be
reported through the applicable OpenAI security channel; this repository is not
an OpenAI intake endpoint.

The following are known non-security-complete areas in v1:

- verification-policy authenticity and distribution;
- concurrent journal writers;
- OS-native process creation identity;
- encrypted artifact storage and deletion;
- multi-artifact claims;
- production Codex integration.

