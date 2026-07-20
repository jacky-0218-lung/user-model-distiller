# GitHub repository hardening

Apply this checklist after the public repository exists and before the first release. Repository settings live on GitHub and cannot be guaranteed by files in the source tree alone.

## Required baseline

1. Set the default branch to `main` and disallow force pushes and branch deletion.
2. Create a branch ruleset for `main` that requires a pull request, requires the CI and CodeQL checks, requires the branch to be current, dismisses stale approvals, and blocks bypass except emergency repository-administrator recovery.
3. Set the default `GITHUB_TOKEN` permission to read-only and prevent Actions from approving pull requests.
4. Allow only GitHub-owned Actions and require actions to be pinned to a full commit SHA. The repository guard independently rejects mutable `uses:` references and `pull_request_target`.
5. Enable dependency graph, Dependabot alerts, Dependabot security updates, CodeQL default setup or the checked-in CodeQL workflow, secret scanning, and push protection where the account plan supports them.
6. Enable private vulnerability reporting. Keep exploit details and all real session data out of public issues.
7. Enable immutable releases when available. Protect `v*` tags from updates and deletion.
8. Create a protected `release` environment and require manual maintainer approval. The release workflow refuses lightweight tags and tags whose target is not reachable from `main`; the tag ruleset must additionally prevent tag replacement or deletion.
9. Require web-based commit signoff or signed commits if it fits the maintainer's signing setup; do not weaken other controls merely to accommodate unsigned automation.

GitHub documents the relevant controls in its guides for [secure use of Actions](https://docs.github.com/en/actions/reference/security/secure-use), [repository Actions permissions](https://docs.github.com/en/rest/actions/permissions), [repository rulesets](https://docs.github.com/en/rest/repos/rules), and [secret scanning](https://docs.github.com/en/rest/secret-scanning/secret-scanning).

## Checked-in enforcement

- Every workflow starts with `contents: read`; only the minimal publish job receives `contents: write`. The separate attestation job receives only `id-token: write` and `attestations: write`. Neither privileged job checks out or executes repository code.
- Checkout and CodeQL actions are pinned to full 40-character commit SHAs.
- Checkout credentials are not persisted.
- CI compiles all Python, runs the entire synthetic test suite, and runs the repository privacy guard.
- The release workflow accepts only an annotated version tag reachable from `main`, rebuilds and verifies the deterministic bundle in a read-only job, passes the closed artifact set through the Actions artifact service to an isolated attestation job, and publishes only after the protected release environment approves it.
- Dependabot checks both Actions and Python package metadata.
- `CODEOWNERS`, pull-request templates, a private-reporting security policy, and synthetic-only issue templates are present.

## Verification after publication

Use GitHub's Settings pages or REST API to read back every setting. Do not rely on a successful write response alone. Then open a synthetic pull request and confirm:

- unpinned workflow actions are rejected by CI;
- required checks prevent merge while failing;
- direct or force pushes to `main` are rejected;
- a fake test secret is blocked before it reaches the repository;
- a deleted or moved `v*` tag is rejected;
- the release ZIP reproduces locally and passes `tools/build_release.py verify`.

Record the verification date and repository URL in the first release notes. Never include tokens, local paths, session identifiers, or screenshots containing private account data.
