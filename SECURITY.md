# Security policy

## Supported versions

Security fixes are applied to the latest release and the `main` branch during the alpha period.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting feature in the repository's Security tab. Do not open a public issue when a report contains an exploit, private session data, credentials, or a memory-poisoning payload that could harm users.

Include:

- the affected version or commit;
- a minimal synthetic reproduction;
- expected and observed behavior;
- impact and suggested mitigation, if known.

Do not include real ChatGPT exports or another person's data. Reports will be acknowledged and triaged through the private advisory thread.

## Security boundaries

The project assumes that transcripts and imported archives are untrusted. Its primary risks are:

- malicious ZIP entries or decompression bombs;
- secrets and private identifiers in imported text;
- assistant, tool, or retrieved content poisoning a durable profile;
- stale or conflicting preferences affecting later responses;
- accidental publication of normalized histories or profiles;
- compromised GitHub Actions dependencies.

Mitigations include bounded in-memory ZIP reads without extraction, path and compression checks, role attribution, approval-gated activation, schema validation, atomic writes, restrictive output permissions where supported, privacy-focused `.gitignore` rules, pinned GitHub Actions, CodeQL, and Dependabot. The external-review workflow emits a minimum-field pack only after a strict privacy gate passes and stores its source mapping under a separately isolated parent.

Secret scanning, push protection, private vulnerability reporting, branch rulesets, and immutable releases are repository-host settings. Maintainers must enable and read back these controls using [the GitHub hardening checklist](docs/github-hardening.md); their presence cannot be inferred from checked-in files alone.

## Operator responsibility

Keep session exports and generated artifacts in a private directory outside the repository. Review candidates before approval. Deleting a record from this tool cannot delete copies stored by unrelated services, backups, or platforms; report those boundaries honestly.
