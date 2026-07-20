# Threat model

## Scope

This model covers the local import, evidence selection, profile review, compilation, repository, and release workflow. It does not cover the security of ChatGPT, Codex, operating-system backups, or third-party services outside this project.

## Assets

- Raw conversation exports.
- Normalized messages and evidence queues.
- Approved preference profiles and compiled runtime views.
- Global startup guidance and digest-bound bridge plans.
- Source provenance and deletion state.
- Repository integrity and release artifacts.

## Trust boundaries

```text
Untrusted archive / transcript
             |
             v
Bounded local normalizer -- common-secret redaction
             |
             v
Untrusted evidence queue -- human review and schema validation
             |
             v
Approved profile -- filtered compiler
             |
             v
Low-volume runtime preferences
             |
             v
Receipt-approved global AGENTS.md bridge
```

Imported content remains untrusted after parsing. Approval changes whether a preference may be used, not whether it can override system, safety, legal, or workspace rules.

## Principal threats and controls

| Threat | Impact | Controls |
|---|---|---|
| ZIP traversal, links, encryption, or decompression bomb | File overwrite or resource exhaustion | Never extract members; reject traversal, links, encrypted entries, oversized data, and extreme ratios |
| Credentials in transcripts | Disclosure through intermediate files or commits | Default redaction, high-privacy mode, private output permissions, ignore rules, GitHub push protection |
| Assistant or tool memory poisoning | Persistent behavior manipulation | Normalize only user and assistant dialogue; evidence candidates only from user role; approval gate; no source quotes in runtime view |
| Malicious external identifiers | Markdown injection or confusing provenance | Replace unsafe session and message identifiers with stable hashes |
| Incorrect or stale preference | Repeated bad output | Confidence, scope, timestamps, supersession, explicit review, current-request precedence |
| Sensitive inference | Privacy harm or discrimination | Prohibited-category policy; sensitive exclusion by default; no automatic activation |
| Incomplete deletion | Continued unwanted personalization | Profile removal, recompilation, cache/index checks, honest reporting of external copies |
| Accidental public commit | Permanent privacy exposure | Synthetic-only contribution policy, privacy-focused ignore rules, repository guard, secret scanning |
| Workflow supply-chain compromise | Code execution in CI | Read-only default token, full-SHA action pins, disabled persisted checkout credentials, Dependabot |
| Unbounded profile growth | Cost, distraction, reduced quality | Record and evidence limits; compact compiler; task-relevant retrieval guidance |
| Global guidance overwrite or confused-deputy update | Loss of unrelated instructions or persistent behavior injection | Unique markers; exact plan digest; compare-before-write hash; atomic replacement; preserve all unmarked content |
| Runtime-view substitution | Persistent malicious instructions | Private stable path; regular-file and link checks; generated-header validation; no provenance; approved-profile compiler; current-request and higher-priority-rule precedence |
| Direct edits to host memory state | Corruption, privacy loss, or unsupported behavior | Never edit `~/.codex/memories/`; use Codex Settings and `/memories`; keep native memory separate from the deterministic bridge |

## Residual risks

- Regex redaction cannot detect every secret or identifier.
- Heuristic evidence selection can miss preferences or flag one-off instructions.
- A user may approve an incorrect candidate.
- Local malware or a compromised model/runtime can access files outside this project's controls.
- Deleting a local profile cannot delete copies retained by unrelated platforms or backups.
- Native memory generation is asynchronous and controlled by Codex; a Skill cannot guarantee when an eligible chat is consolidated.

## Release gates

- Unit and end-to-end tests pass.
- Repository guard passes.
- Skill validation passes.
- CodeQL has no unresolved high or critical alert.
- No high-severity non-user memory-write case succeeds in the synthetic adversarial suite.
- Release archive has a published SHA-256 checksum.
