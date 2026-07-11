# Compaction Summary Records Partial Stdout from Timed-Out Commands as Confirmed Results

**Hiroki Tamba**
ORCID: 0009-0004-7635-0741

Date: 2026-07-11

## Abstract

This technical note documents a failure mode in Claude Code's session compaction mechanism whereby partial terminal output from timed-out commands (exit code 143 / SIGTERM) is recorded in the compaction summary as if the command completed successfully. Subsequent sessions inherit these false positives as confirmed facts. No exit code warning, no "unconfirmed" flag, and no re-verification mechanism exists. The finding is independently reproducible and affects any agentic LLM tool that employs session compaction or context summarization.

## 1. Environment

- Claude Code v2.1.205 / v2.1.207 (observed across both)
- Windows 11
- Long session with multiple tool calls leading to compaction

## 2. Observed Behavior

When a long-running command times out in Claude Code, the process is killed with exit code 143 (SIGTERM). Terminal output captured before the kill — partial, potentially mid-line — is included in the session's compaction summary without any indication that the command did not complete.

A batch of API calls timed out mid-execution. The session summary reported the first two iterations as "completed with specific results." A new session read that summary and treated them as established data points. Independent verification of the actual output file revealed that every single entry had failed. The "confirmed results" existed only in ephemeral stdout from a killed process.

The failure is silent: there is no signal to the user or the model that the "confirmed" results exist only in ephemeral stdout and not in any persistent store.

## 3. Mechanism

Session compaction in Claude Code operates on the conversation transcript, which includes tool call results. When a Bash command produces stdout before being killed by a timeout, that stdout is captured as the tool result. The compaction algorithm summarizes the session state including these tool results. At no point does the compaction logic:

1. Check the exit code of commands whose output it summarizes
2. Flag outputs from non-zero exit codes as unconfirmed
3. Distinguish between "observed in terminal" and "persisted to file"
4. Trigger re-verification of claimed results in subsequent sessions

## 4. Structural Relation to Issue #66273

This finding is structurally related to anthropics/claude-code#66273 (observer-aware protocol / self-favoring asymmetric skepticism). Both are instances of the same underlying problem: Claude cannot accurately evaluate its own operational outputs.

- **#66273** covers asymmetric skepticism toward self-generated content versus external sources — the model over-trusts its own outputs while scrutinizing external content.
- **#76584** covers the failure to distinguish between observed-but-not-persisted and confirmed-and-persisted states in session handoff.

The common root is the absence of a verification layer between observation and assertion. The model treats "I saw it in stdout" as equivalent to "it happened and was recorded," which is epistemically unsound when the process producing that stdout was killed before completion.

## 5. Scope of Impact

This failure mode is not specific to Claude Code. Any agentic LLM tool that employs session compaction or context summarization — including Codex, Devin, Cursor, Jules, and similar systems — shares the same architectural pattern: long-running tool calls produce partial output, context windows compress that output into summaries, and subsequent turns treat summaries as ground truth.

For anyone using agentic LLM tools for data processing, research, or API interactions: verify output files independently. Do not trust session summaries as confirmation that operations succeeded.

## 6. Reproduction

The finding is reproducible by:

1. Starting a Claude Code session with a long-running batch command (e.g., sequential API calls with processing)
2. Allowing the command to time out (default 120s or custom timeout)
3. Observing that partial stdout is recorded in the session transcript
4. Continuing the session until compaction occurs
5. Starting a new session or allowing context summarization
6. Observing that the compaction summary reports partial results as confirmed

Exit code 143 is deterministic for SIGTERM-killed processes. The compaction behavior is deterministic given the transcript content.

## 7. Relation to Prior Work

This note is a companion to:

- arXiv:2606.26185 — LLM-judge nondeterminism in evaluation contexts
- Zenodo DOI 10.5281/zenodo.20609109 — Reproduction test report for #66273
- Zenodo DOI 10.5281/zenodo.20612989 — Observer-aware red-teaming protocol

## References

1. anthropics/claude-code#76584: "Compaction summary records partial stdout from timed-out commands as confirmed results"
2. anthropics/claude-code#66273: "Claude Code (Opus): self-favoring asymmetric skepticism, unstable calibration, and a false-completion claim"
3. Tamba, H. (2026). arXiv:2606.26185. LLM-judge nondeterminism.

## License

CC-BY-NC-ND-4.0. Commercial use requires written permission: contact@tamba-research.academy
