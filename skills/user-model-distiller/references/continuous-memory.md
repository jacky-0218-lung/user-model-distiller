# Continuous memory and startup integration

Use this workflow only when the user explicitly asks for cross-session or ongoing behavior.

Resolve an approved Python 3.10 or newer runtime before running `memory_control.py`. Reject older interpreters even if a smoke test appears to work. In Codex desktop, use the workspace-dependency locator when no compliant global interpreter exists.

## Two distinct layers

1. **Codex native memories** learn useful context from eligible chats and can inject it into later chats. The user controls this in **Settings > Personalization** and with `/memories` per chat. Native memory generation is asynchronous and may skip short, active, externally contextualized, or low-quota chats.
2. **The approved runtime bridge** provides deterministic startup behavior. A marked block in the user's global `AGENTS.md` tells Codex to read one compact `USER_MODEL.md` compiled from digest-approved preferences.

Never describe the runtime bridge as ChatGPT Memory. Never edit generated files under `~/.codex/memories/`; those are host-managed state.

## Enable native memories

Ask the user to enable memories in Codex **Settings > Personalization**. In the current chat, ask them to use `/memories` and allow both:

- using existing local memories;
- contributing this chat to future memories.

Do not change these controls on the user's behalf unless the host exposes an explicit, approval-gated control surface and the user asks for it.

## Install the deterministic startup bridge

First compile only approved preferences to a stable private runtime path. Then create a plan; do not apply it in the same approval step.

```bash
python scripts/memory_control.py plan-install \
  --runtime-view PRIVATE_DIR/USER_MODEL.md \
  --agents-file CODEX_HOME/AGENTS.md \
  --authorization-id BRIDGE_REVIEW_ID \
  --output PRIVATE_DIR/bridge-install-plan.json
```

Show the receipt fields except `after_text`, plus a compact diff of the proposed marked block. Explain that the global `AGENTS.md` is read at the start of every Codex run. Wait for approval of the exact `receipt_digest`.

After approval, apply the same plan without regenerating it:

```bash
python scripts/memory_control.py apply PRIVATE_DIR/bridge-install-plan.json \
  --expected-digest APPROVED_RECEIPT_DIGEST
python scripts/memory_control.py status --agents-file CODEX_HOME/AGENTS.md
```

The apply step refuses changed `AGENTS.md` bytes, a changed plan, unsafe links, a missing or malformed runtime view, and digest mismatch. It preserves unrelated guidance and replaces only the marked block.

## Ongoing updates

- Let native Codex memories collect eligible future chats when the user has enabled contribution.
- Treat explicit durable corrections as new evidence candidates.
- Never activate inferred or transformed rules automatically.
- After the user reviews and digest-approves a profile change, compile the updated approved profile back to the same private `USER_MODEL.md` path. New sessions then read the updated view without reinstalling the bridge.
- Keep the active runtime view compact. Retrieve only three to five task-relevant rules.
- If the user asks to forget a rule, remove it from the profile, recompile the same runtime path, and verify that retrieval no longer returns it.

## Disable or remove

Turning off native memories and removing the deterministic bridge are separate actions. Respect either request independently.

To remove the bridge, create and approve a new exact plan:

```bash
python scripts/memory_control.py plan-remove \
  --agents-file CODEX_HOME/AGENTS.md \
  --authorization-id BRIDGE_REMOVAL_REVIEW_ID \
  --output PRIVATE_DIR/bridge-remove-plan.json
python scripts/memory_control.py apply PRIVATE_DIR/bridge-remove-plan.json \
  --expected-digest APPROVED_RECEIPT_DIGEST
```

The removal keeps all guidance outside the marked block. Use Codex Settings or `/memories` to stop native memory use or contribution.
