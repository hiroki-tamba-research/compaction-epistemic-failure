# Compaction Epistemic Failure

Technical note documenting a bug in Claude Code where compaction summaries record partial stdout from timed-out commands (exit code 143) as confirmed results, propagating false positives across sessions.

- arXiv: https://arxiv.org/abs/2607.13071
- Zenodo DOI: https://doi.org/10.5281/zenodo.21305235
- GitHub issue: https://github.com/anthropics/claude-code/issues/76584
- Related: https://github.com/anthropics/claude-code/issues/66273
- License: CC-BY-NC-ND-4.0
