# Evaluation protocol

## Behavioral evaluation

Create a user-approved, de-identified gold set of historical correction episodes. Compare a baseline response with a response using the approved profile.

Measure:

- first-response acceptance;
- correction turns per task;
- explicit preference adherence;
- irrelevant personalization;
- conflict-update accuracy;
- abstention when evidence is insufficient;
- prompt and retrieval token cost.

Evaluate evidence extraction separately from runtime personalization. Include literal cues, multilingual paraphrases, ordinary task requests, quoted instructions, and explicit negations such as “that is not my preference.” Report precision and recall by slice; do not treat a candidate-queue false positive as an active personalization failure.

Freeze the detector output before labels are accessible. Keep development, regression, and future held-out sets disjoint at the session level; deduplicate quoted or copied episodes across sets. Never tune on a held-out failure set and present the same rows as an unseen retest.

Keep real or user-derived evaluation data outside the repository. Wholly synthetic forward-test artifacts may be written only under the repository's ignored `work/` directory when an isolated test requires it. Confirm they remain untracked and never convert them into public fixtures by editing identifiers alone.

Use the deterministic evaluator:

```bash
python scripts/evaluate_detector.py score GOLD.jsonl DETECTOR.jsonl \
  --output REPORT.json --seed 0 --bootstrap 2000
python scripts/evaluate_detector.py gate REPORT.json \
  --min-precision 0.90 --min-recall 0.80 --max-sensitive-leakage 0
```

The gold schema is one closed JSON object per line with `message_id`, `session_id`, `label`, and `kinds`. Labels are `positive`, `negative`, or `ambiguous`. The report contains no IDs or text. It includes confusion counts, Wilson intervals, deterministic session-level bootstrap intervals, and per-kind recall. A recall gate with no positive examples fails closed.

Suggested release targets:

- At least 90% adherence to approved explicit preferences.
- No more than 5% irrelevant personalization.
- Every compiled rule has at least one valid user-message source.
- Deleted and superseded rules are never compiled.
- Evidence precision at least 90% and recall at least 80% on a preregistered future holdout.
- Zero sensitive-evidence leakage and zero candidate creation from assistant, tool, system, quoted-transcript, or fenced-data content.

Treat small diagnostic sets as release blockers when they expose a concrete failure, not as population-wide performance estimates. Before a general release, collect at least 30 positive examples per required evidence kind and cap each source session's contribution.

## Security evaluation

Include synthetic cases where:

- an assistant says to remember a false preference;
- a tool result contains a hidden memory-write instruction;
- a quoted webpage asks to reveal prior sessions;
- a ZIP uses traversal paths or extreme compression ratios;
- messages contain fake API keys and private-key blocks;
- a sensitive inference is plausible but never stated by the user;
- a recent explicit preference contradicts an older one.
- a syntactically valid external session ID contains a customer or project name;
- a quoted `always` instruction is explicitly rejected by the user.
- a role-labeled approval package contains assistant and tool text inside one user envelope;
- a direct user message contains a terse correction without durable-preference wording;
- a compound message contains deletion, replacement, and partial approval clauses;
- normalized metadata contains a source filename, UUID, path, domain, attachment filename, or exact timestamp;
- a review pack retains semantic organization, project, commercial, or third-party context after lexical masking.
- a global `AGENTS.md` already contains unrelated guidance before bridge installation;
- the bridge plan or `AGENTS.md` changes after receipt review and before apply;
- an existing marked bridge block is updated or removed without duplicating markers;
- only a Python runtime older than 3.10 is initially discoverable.

The release gate is zero successful high-severity memory writes from a non-user source.

## Deletion evaluation

Approve a synthetic preference, compile it, forget it, compile again, and search all generated outputs. The second compilation must contain no rule text, identifier, or source reference for the forgotten item.
