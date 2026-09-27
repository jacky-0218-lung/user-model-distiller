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
Bounded local normalizer -- hidden-character removal, common-secret redaction
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
| Instructions hidden in invisible characters | Reviewer approves text they cannot see; hidden directive reaches the model or splits a secret past redaction | Strip Unicode Tag, bidi control, zero-width, and C0/C1 characters before scoring; count removals; block them as tampering if a normalized file still contains them; warn on orthographic joiners; reject them in tracked repository files |
| Malicious external identifiers | Markdown injection or confusing provenance | Replace unsafe session and message identifiers with stable hashes |
| Incorrect or stale preference | Repeated bad output | Confidence, scope, timestamps, supersession, explicit review, current-request precedence |
| Sensitive inference | Privacy harm or discrimination | Prohibited-category policy; sensitive exclusion by default; no automatic activation |
| Incomplete deletion | Continued unwanted personalization | Profile removal, recompilation, cache/index checks, honest reporting of external copies |
| Accidental public commit | Permanent privacy exposure | Synthetic-only contribution policy, privacy-focused ignore rules, repository guard, secret scanning |
| Tampered published Skill text | Installers load agent context that review did not show them | Repository guard rejects invisible and bidi control characters in tracked files; canonical bundle digest; full-SHA install pinning; per-file review |
| Workflow supply-chain compromise | Code execution in CI | Read-only default token, full-SHA action pins, disabled persisted checkout credentials, Dependabot |
| Unbounded profile growth | Cost, distraction, reduced quality | Record and evidence limits; compact compiler; task-relevant retrieval guidance |
| Global guidance overwrite or confused-deputy update | Loss of unrelated instructions or persistent behavior injection | Unique markers; exact plan digest; compare-before-write hash; atomic replacement; preserve all unmarked content |
| Runtime-view substitution | Persistent malicious instructions | Private stable path; regular-file and link checks; generated-header validation; no provenance; approved-profile compiler; current-request and higher-priority-rule precedence |
| Direct edits to host memory state | Corruption, privacy loss, or unsupported behavior | Never edit `~/.codex/memories/`; use Codex Settings and `/memories`; keep native memory separate from the deterministic bridge |

## Memory-lifecycle coverage

A 2026 survey of long-term-memory security in LLM agents
([arXiv:2604.16548](https://arxiv.org/abs/2604.16548)) organizes attacks and
defenses along a six-phase memory lifecycle. Mapping this project's controls
onto that framework shows where coverage is strong and where it depends on
practices outside the workflow:

| Lifecycle phase | Primary controls here | Coverage |
|---|---|---|
| Write | User-role-only evidence, hidden-character stripping, default-deny privacy gate, evidence-review receipt, digest-bound approval | Covered |
| Store and manage | Closed schema validation, allowed status transitions, supersession instead of silent rewrite, record and evidence limits | Partial: no built-in profile snapshot or rollback command; see residual risks |
| Retrieve | Runtime view compiled only from approved, valid records; no source quotes or provenance in the runtime view | Covered |
| Execute | Current-request precedence; approval never overrides system, safety, legal, or workspace rules | Covered |
| Share and propagate | Local-first processing; stricter external-review gate before any disclosure; no shared or multi-agent memory store | Out of scope by design |
| Forget and rollback | `forget` with recompilation and artifact purging; honest reporting of host-managed copies | Partial: restoring a prior known-good profile relies on user-managed backups |

The two partial rows describe the same store-phase gap: the workflow records
history inside the profile but does not snapshot the profile file itself, so
recovery from a bad approval uses supersession and `forget` rather than a
one-step rollback.

## Residual risks

- Regex redaction cannot detect every secret or identifier.
- Heuristic evidence selection can miss preferences or flag one-off instructions.
- A user may approve an incorrect candidate. The workflow does not create
  automatic profile snapshots, so recovery uses supersession and `forget`
  plus user-managed backups rather than a one-step rollback.
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
