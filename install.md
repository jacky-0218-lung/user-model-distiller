# Secure installation plan

Install only after the user approves an integrity-bound receipt for the exact
bytes that will be installed.

## Package identity

- Repository: `jacky-0218-lung/user-model-distiller`
- Skill name: `user-model-distiller`
- Skill source: `skills/user-model-distiller`
- Runtime: Python 3.10 or later
- Network access: none required by the included scripts
- External Python dependencies: none

## Immutable source and staging

1. Confirm the repository owner and HTTPS origin.
2. Resolve the selected branch, tag, or release exactly once to a full 40-character commit SHA. An abbreviated SHA, branch name, tag name, or other mutable label is not an approved source identity.
3. Create a new private staging directory that is readable only by the installing user when the platform supports access controls.
4. Fetch `install.md` and the complete `skills/user-model-distiller` subtree from that exact commit. Every later source request must use the same full commit SHA.
5. Reject symbolic links, non-regular files, absolute paths, and paths that escape the staged Skill root. Include every regular file below the staged Skill root; do not silently omit hidden or unexpected files.
6. Do not request access to chat histories during installation.
7. Do not execute any downloaded script merely to install or verify the Skill.

## Canonical bundle digest

Calculate the canonical bundle digest from the private staging directory before review:

1. Enumerate every regular file below the staged `skills/user-model-distiller` directory.
2. Express each relative path as a UTF-8 POSIX path, with `/` separators, and sort files by those path bytes in bytewise order.
3. Start a SHA-256 stream with the exact ASCII bytes `user-model-distiller-bundle-v1`, followed by one zero byte.
4. For each sorted file, append the path's UTF-8 byte length as an unsigned 8-byte big-endian integer, the path bytes, and the file's 32 raw SHA-256 digest bytes, in that order.
5. The lowercase hexadecimal digest of the completed stream is the canonical bundle digest.

The digest covers file contents, names, and layout. Any source change, including a change that preserves the same filenames, creates a different approval subject.

For an already-trusted local checkout, `tools/skill_bundle.py` is the audited reference implementation for generating a receipt or verifying an expected digest. It rejects links, junctions, and non-regular files and never copies the bundle. Review that tool before executing it; do not use it as a substitute for reviewing untrusted source.

```text
PYTHON tools/skill_bundle.py receipt STAGED_SKILL --repository OWNER/REPO --origin HTTPS_ORIGIN --commit FULL_SHA --destination DESTINATION --output approval-receipt.json
PYTHON tools/skill_bundle.py verify COPIED_SKILL --expected APPROVED_DIGEST
```

Replace `PYTHON` with an approved Python 3.10+ executable. On Windows this may be `py -3`; in Codex desktop the agent can locate the bundled workspace runtime when no global Python is installed.

## Review and approval

1. Review the staged `SKILL.md`, every file under `scripts/`, `references/security-and-privacy.md`, and every other staged file.
2. Confirm the destination is the user's trusted Skill directory.
3. Show the user an **Approval receipt** containing:
   - repository and HTTPS origin;
   - full commit SHA;
   - canonical bundle digest;
   - complete relative file list; and
   - destination path and whether it already exists.
4. Summarize the permissions and security boundaries, then ask the user to approve that exact receipt. A general approval of the repository, branch, or Skill name is insufficient.

## Install

1. **Do not re-fetch** after approval. Recalculate the staged bundle digest immediately before copying. If it differs from the approved digest, refuse the installation and obtain a new review and Approval receipt.
2. Copy only the same staged bytes to a new temporary directory under the trusted Skill root. Do not copy repository tests, workflows, or documentation into the Skill root.
3. Recalculate the canonical bundle digest from the temporary destination. If it does not equal the approved digest, refuse the installation, remove only the new temporary copy, and leave any existing installation unchanged.
4. If an installation already exists, show its complete diff against the verified temporary copy and obtain renewed approval tied to the new Approval receipt.
5. Only after all checks pass, rename or replace the verified temporary directory as `user-model-distiller`. Prefer an atomic rename when the platform supports it.

Never copy directly over an existing installation and never continue after an integrity mismatch.

## Verify

After the verified replacement:

1. Confirm `SKILL.md` begins with `name: user-model-distiller`.
2. Run the platform's Skill validator when one is available.
3. Do not run downloaded scripts merely as an installation check.
4. Report a final receipt with the installed path, complete file list, full commit SHA, and canonical bundle digest.

## First use

Ask the user to choose a specific authorized export or session directory and a separate private output directory. Default to preview-only processing. Never publish, upload, or commit the resulting files.
