# Profile schema

Use `profile.json` as the auditable source of truth. Use `USER_MODEL.md` only as a generated runtime view.

- [Root object](#root-object)
- [Preference record](#preference-record)
- [Allowed values](#allowed-values)
- [Rules](#rules)
- [Temporal semantics](#temporal-semantics)

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

## Temporal semantics

Four timestamps describe different events. Do not read any one of them as another.

- `first_observed` and `last_observed` bound the **evidence window**: the earliest and latest moment the supporting evidence was observed. They say when the user expressed the preference, not when the rule became usable.
- `approval.approved_at` records when the rule became **eligible for compilation**. A candidate is never compiled, so a rule has no active period before this field exists.
- `expires_at` bounds the **end of validity** and is exclusive: compilation drops a rule once `expires_at` is at or before the evaluation instant. `null` means "until superseded or forgotten", not "true forever".
- Root `updated_at` records the last write to the file. It is file metadata; never read it as the moment a particular rule changed.

### Reconstructing the rule that applied at a past instant

The profile keeps enough history to answer this, but the answer is derived rather than stored:

1. A replacement records `supersedes: [OLD_ID]`, and the superseded record moves to `status: superseded` in the same validated write.
2. The supersession therefore happened at the **replacement's** `approval.approved_at`. There is deliberately no `superseded_at` field: a second timestamp for the same event could disagree with the approval it came from.
3. To find the rule that applied at instant `T`, walk the supersession chain and take the record whose own `approval.approved_at` is at or before `T` and whose replacement, if any, was approved after `T`.

Prefer `add-candidate --supersedes OLD_ID` over `set-status superseded` when a rule is being replaced. Retiring a rule with `set-status` leaves no replacement approval to date the change, so that step is only reconstructible from external records.

### What `--as-of` does and does not do

`compile --as-of T` evaluates **expiry only** against `T`. It does not reconstruct historical status: a record that is superseded or rejected today stays out of the compiled view even when `T` precedes that change. Use it to preview an expiry boundary, not as an audit tool. Read the profile itself for history.

### Staleness

An approved preference can become confidently wrong when the user's circumstances change and the rule never expires. Handle that by review, not by silent decay. When a correction arrives, create a new evidence-backed record that supersedes the old one; never edit an approved rule in place, and never let elapsed time alone downgrade or remove a rule the user approved.

Compilation honours `expires_at`, but no bundled command sets it: `add-candidate` always writes `null`. Until one does, express a preference the user already expects to be temporary with a `temporary` scope, which compiles only when its exact context ID is supplied.
