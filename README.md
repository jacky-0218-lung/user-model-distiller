# User Model Distiller

[![CI](https://github.com/jacky-0218-lung/user-model-distiller/actions/workflows/ci.yml/badge.svg)](https://github.com/jacky-0218-lung/user-model-distiller/actions/workflows/ci.yml)
[![CodeQL](https://github.com/jacky-0218-lung/user-model-distiller/actions/workflows/codeql.yml/badge.svg)](https://github.com/jacky-0218-lung/user-model-distiller/actions/workflows/codeql.yml)

A local-first Codex Skill that turns authorized chat histories into a reviewable, evidence-backed model of how a user prefers to work.

The project is designed to reduce repeated correction without silently profiling the user. Candidate preferences do not become active until the user reviews them.

> Alpha software. Use synthetic or backed-up data while evaluating it.

## What it does

- Imports user-supplied ChatGPT exports and supported JSON or JSONL session logs.
- Follows the active ChatGPT conversation branch instead of mixing abandoned alternatives.
- Ignores system and tool messages as preference sources.
- Replaces external session and message identifiers with stable local pseudonyms.
- Removes source filenames and redacts common credentials, contact identifiers, UUIDs, URLs, paths, domains, attachment names, long identifiers, and commercial amounts in high-privacy mode.
- Runs a fail-closed privacy gate before evidence creation and a stricter gate before any external review.
- Finds likely explicit preferences, corrections, and approvals for review.
- Publishes complete preview runs atomically with a path-free SHA-256 manifest.
- Requires reviewed evidence and digest-bound user approval before activation.
- Validates a closed preference profile with provenance, scope, expiry, and legal state transitions.
- Compiles only approved, active preferences into a compact runtime view.
- Supports superseding and forgetting profile entries.

## What it does not do

- It does not log in to, scrape, or bypass access controls on ChatGPT.
- It does not automatically read every account conversation.
- It does not upload histories to a memory service.
- It does not treat model or tool output as truth about the user.
- It does not infer protected traits or create a psychological profile.
- It does not modify ChatGPT Memory or Codex memory files without an explicit request.

## Install with an agent

Give your agent this instruction:

> Resolve `jacky-0218-lung/user-model-distiller` once to a full 40-character commit SHA. Fetch `install.md` and `skills/user-model-distiller` from that exact commit into a new private staging directory. Review the staged files, calculate the canonical bundle digest defined in `install.md`, and show me the Approval receipt containing the repository, commit, digest, file list, and destination. After I approve that exact receipt, Do not re-fetch. Copy only the same staged bytes, verify the staging and installed digests both match the approved digest, and refuse the installation on any mismatch. Do not execute downloaded scripts merely to install the Skill.

This binds approval to immutable content instead of a mutable branch. The installation guide also avoids `curl | shell` and other remote-code execution patterns.

## Manual install

Use a Git client or GitHub's archive endpoint to resolve the version you want to a full commit SHA, stage the exact commit privately, and follow [install.md](install.md) to review and verify its canonical bundle digest before copying anything. Do not copy from an arbitrary mutable checkout.

Install the verified `skills/user-model-distiller` subtree into your agent's trusted Skill directory. For Codex this is normally:

```text
$CODEX_HOME/skills/user-model-distiller
```

When `CODEX_HOME` is unset, use the `.codex/skills/user-model-distiller` directory under your user profile. Restart or open a new task after installation if the Skill is not discovered immediately.

## Private workflow

Keep all inputs and outputs outside the repository, preferably under a dedicated private directory.

The examples use `python3`. On Windows, use `py -3` when Python 3.10 or later is installed, or provide the full path to an approved runtime. In Codex desktop, ask Codex to locate its bundled workspace Python when neither command is available.

```bash
python3 skills/user-model-distiller/scripts/distill_workflow.py preview chatgpt-export.zip \
  --output-dir /private/user-model-run-001 \
  --authorization-id source-review-001 --privacy high
python3 skills/user-model-distiller/scripts/distill_workflow.py verify \
  /private/user-model-run-001

python3 skills/user-model-distiller/scripts/prepare_review_pack.py prepare \
  /private/user-model-run-001/evidence.jsonl \
  --output-dir /private/external-review-pack-001 \
  --mapping-output /access-isolated/review-map-001.json \
  --authorization-id disclosure-approval-001
python3 skills/user-model-distiller/scripts/prepare_review_pack.py verify \
  /private/external-review-pack-001

python3 skills/user-model-distiller/scripts/profile_tool.py review-evidence \
  /private/user-model-run-001/evidence.jsonl \
  --message-id MESSAGE_ID --decision accepted \
  --authorization-id evidence-review-001 \
  --output /private/user-model-review-001/reviewed-evidence.jsonl
python3 skills/user-model-distiller/scripts/profile_tool.py add-candidate \
  /private/user-model-run-001/profile.json \
  /private/user-model-review-001/reviewed-evidence.jsonl \
  --id pref_conclusion_first --rule "Lead with the conclusion." \
  --category response_style --confidence 0.9 \
  --message-id MESSAGE_ID \
  --output /private/user-model-review-001/candidate-profile.json
python3 skills/user-model-distiller/scripts/profile_tool.py candidate-digest \
  /private/user-model-review-001/candidate-profile.json pref_conclusion_first
python3 skills/user-model-distiller/scripts/profile_tool.py approve \
  /private/user-model-review-001/candidate-profile.json pref_conclusion_first \
  --authorization-id candidate-approval-001 \
  --expected-digest REVIEWED_DIGEST \
  --output /private/user-model-review-001/approved-profile.json
python3 skills/user-model-distiller/scripts/profile_tool.py compile \
  /private/user-model-review-001/approved-profile.json \
  --output /private/user-model-review-001/USER_MODEL.md
```

The preview command never approves or compiles a rule. Keep its verified artifacts immutable; write review and approval revisions to a separate private directory. `add-candidate` accepts only explicitly reviewed direct-user evidence; `approve` requires the digest of the exact candidate the user saw. Scoped rules compile only when their project, task, or temporary context is supplied.

The external review pack is optional. It contains only random review IDs, evidence kinds, and user text. Any privacy warning—including a standalone or Unicode-separator domain—blocks publication. The source-ID mapping must be written under a different access-controlled parent. If that parent is absent, the tool creates it owner-only; an existing shared or inherited-access parent is rejected. A passing pack still requires a separate user decision before disclosure to a hosted reviewer.

## Security model

Imported transcripts are untrusted. Only user-authored evidence may become a preference candidate, and only explicit user approval may activate it. Source quotes are kept out of the compiled runtime prompt to reduce persistent prompt-injection risk.

See [SECURITY.md](SECURITY.md), the [threat model](docs/threat-model.md), and the Skill's [security policy](skills/user-model-distiller/references/security-and-privacy.md) before using real histories.

## Development

The runtime scripts use only the Python standard library and support Python 3.10 or later.

```bash
python3 -m unittest discover -s tests -v
python3 tools/check_repository.py
python3 -m compileall -q skills tests tools
```

Build a deterministic release outside the repository and verify it before tagging:

```bash
python3 tools/build_release.py build --output-dir /private/release-0.2.0 \
  --expected-tag v0.2.0 --source-date-epoch 0
python3 tools/build_release.py verify /private/release-0.2.0
```

The release directory contains the Skill ZIP, an SPDX 2.3 SBOM, `SHA256SUMS`, and a closed manifest. Tag pushes run the same tests and publish only these verified artifacts. Repository administrators should apply and verify the settings in [GitHub hardening](docs/github-hardening.md) before the first public release.

Real session data is not accepted in issues, pull requests, tests, or examples. Use minimal synthetic fixtures.

## Status and limitations

- Import formats can change as upstream export schemas evolve.
- Evidence detection is multilingual but heuristic. Provenance envelopes, quotations, negation, terse corrections, and compound clauses remain mandatory evaluation slices.
- High privacy is de-identification risk reduction, not guaranteed anonymity. Semantic organization, project, relationship, and third-party context can survive lexical masking; the external-review gate blocks on these warnings.
- Model-assisted review is never automatic. Hosted review requires a separate disclosure, a user-only minimum-field pack, a passing external-review privacy report, and user approval.
- High-quality consolidation still requires model-assisted review or manual editing.
- Continuous cross-session synchronization requires a separately authorized connector or application; a Skill alone does not grant account access.

## License

Apache License 2.0. See [LICENSE](LICENSE).
