# Profile schema

Use `profile.json` as the auditable source of truth. Use `USER_MODEL.md` only as a generated runtime view.

## Root object

```json
{
  "schema_version": "1.1",
  "updated_at": "2026-07-19T00:00:00Z",
  "preferences": []
}
```

## Preference record

```json
{
  "id": "pref_response_conclusion_first",
  "rule": "Lead with the outcome before explaining the process.",
  "category": "response_style",
  "scope": {"type": "global", "value": null},
  "confidence": 1.0,
  "status": "candidate",
  "sensitivity": "normal",
  "first_observed": "2026-07-01T00:00:00Z",
  "last_observed": "2026-07-19T00:00:00Z",
  "evidence": [
    {
      "session_id": "session-abc",
      "message_id": "message-123",
      "kind": "explicit_preference"
    }
  ],
  "supersedes": [],
  "expires_at": null,
  "approval": null
}
```

After digest-bound approval, `approval` is:

```json
{
  "authorization_id": "approval-20260720-001",
  "candidate_digest": "64-lowercase-hex-characters",
  "approved_at": "2026-07-20T00:00:00Z"
}
```

## Allowed values

- `category`: `response_style`, `format`, `language`, `collaboration`, `tooling`, `research`, `coding`, `writing`, `decision_making`, `accessibility`, `project`, `other`
- `scope.type`: `global`, `task`, `project`, `temporary`
- `status`: `candidate`, `approved`, `rejected`, `superseded`
- `sensitivity`: `normal`, `sensitive`, `prohibited`
- `evidence.kind`: `explicit_preference`, `correction`, `approval`, `repeated_request`

## Rules

- Keep `id` stable and limited to lowercase ASCII letters, numbers, underscores, periods, and hyphens.
- Keep `rule` below 500 characters and write it as an actionable instruction.
- Use `scope.value` only for task, project, or temporary scopes.
- Keep `confidence` between 0 and 1.
- Require at least one evidence item before approval.
- Treat the schema as closed. Reject missing and unknown root, preference, evidence-reference, and approval fields.
- Accept candidate evidence only after `review-evidence` records a user decision and authorization ID. Reject indirect or truncated evidence.
- Bind approval to the canonical digest of the exact candidate rule, scope, confidence, sensitivity, provenance, supersession links, and expiry.
- Change an approved replacement and the rules it supersedes in one validated write.
- Never approve `prohibited` records.
- Compile global rules by default. Include project, task, or temporary rules only when the exact context ID matches.
- Compile sensitive records only when their exact IDs are separately authorized; never use a blanket include switch.
- Treat invalid expiry values as errors, not as non-expiring records.
- Keep source quotes in the review workspace, not in the durable profile.
- Store no raw file paths, source filenames, source hashes, quotes, or external identifiers in the durable profile. Use only the pseudonymous session and message IDs emitted by normalization.
