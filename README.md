# User Model Distiller

[![CI](https://github.com/jacky-0218-lung/user-model-distiller/actions/workflows/ci.yml/badge.svg)](https://github.com/jacky-0218-lung/user-model-distiller/actions/workflows/ci.yml)
[![CodeQL](https://github.com/jacky-0218-lung/user-model-distiller/actions/workflows/codeql.yml/badge.svg)](https://github.com/jacky-0218-lung/user-model-distiller/actions/workflows/codeql.yml)

[繁體中文](#繁體中文) | [English](#english)

## 繁體中文

User Model Distiller 是一個以本機處理為優先的 Codex Skill。它會把使用者明確授權的對話紀錄，整理成可審查、有證據來源的工作偏好模型，讓 AI 更了解使用者希望如何合作與接收答案。

本專案的目標是減少使用者反覆修正 AI 輸出的負擔，同時避免在未告知的情況下建立個人側寫。任何候選偏好都必須先經過使用者審查與明確核准，才會成為可使用的偏好。

> 本專案仍處於 Alpha 階段。評估時請先使用合成資料或已有備份的資料。

### 它能做什麼

- 匯入由使用者提供的 ChatGPT 匯出檔，以及支援的 JSON 或 JSONL session 紀錄。
- 只追蹤 ChatGPT 對話中目前有效的分支，不會把已放棄的回答分支混在一起。
- 不把 system 訊息或工具輸出當成使用者偏好的證據。
- 將外部 session 與訊息識別碼替換為穩定的本機假名識別碼。
- 在高隱私模式下，移除來源檔名，並遮蔽常見憑證、聯絡資訊、UUID、網址、路徑、網域、附件名稱、長識別碼及商業金額。
- 在建立證據前執行預設拒絕的隱私閘門；若要交由外部審查，還會執行更嚴格的檢查。
- 找出可能的明確偏好、修正與核准內容，交由使用者審查。
- 以原子方式發布完整的預覽結果，並附上不含路徑資訊的 SHA-256 manifest。
- 只有在證據已審查，且使用者核准與內容摘要綁定後，才允許啟用偏好。
- 驗證封閉格式的偏好設定檔，包括來源、適用範圍、到期時間與合法狀態轉換。
- 只把已核准且有效的偏好編譯成精簡的執行階段內容。
- 支援用新偏好取代舊偏好，以及忘記指定偏好。

### 它不會做什麼

- 不會登入、爬取 ChatGPT，或繞過任何存取控制。
- 不會自動讀取帳號中的所有對話。
- 不會把對話紀錄上傳到記憶服務。
- 不會把模型或工具輸出視為關於使用者的事實。
- 不會推論受保護的個人特徵，也不會建立心理側寫。
- 未經明確要求，不會修改 ChatGPT Memory 或 Codex 的記憶檔案。

### 快速安裝（建議）

大多數 Codex 桌面版、CLI 與 IDE 使用者可以把下面這段指示交給 Agent：

> 使用 `$skill-installer` 從 `https://github.com/jacky-0218-lung/user-model-distiller/tree/9afdd7b5d09361ddebe09918c6f8aaae897964b0/skills/user-model-distiller` 安裝 `user-model-distiller`。優先使用公開 repository 的直接下載方式；只有直接下載因驗證或權限問題無法使用時，才退回 Git。不要執行 Skill 內下載的腳本。若目的地已存在，請停止並告知，不要直接覆蓋。安裝完成後，回報安裝路徑，並告訴我何時可以開始使用。

這個來源固定在 `v0.2.3` 的完整 commit SHA，不會因 `main` 後續變更而改變。內建安裝器會優先直接下載，因此一般不需要建立暫存 Git repository、自訂 Windows ACL 或設定 `safe.directory`。安裝完成後，Skill 會在下一回合可用；若未出現，請重新啟動 Codex。

### 高保證安裝（選用）

若組織需要逐檔審查、可重現 digest 與核准收據，請把下面這段指示交給 Agent：

> 將 `jacky-0218-lung/user-model-distiller` 的預設分支解析一次為完整的 40 字元 commit SHA。優先用該 commit 的直接 HTTPS archive 完成一次下載，不要只為暫存而建立 Git repository；若必須使用 Git，所有 `.git` 操作必須由同一個作業系統身分完成。只將 `install.md` 與完整的 `skills/user-model-distiller` 子目錄解壓到新的私有暫存目錄。在 Windows 上，暫存 ACL 必須保留安裝流程所需的 Codex 沙箱與核准主機身分，不得假設只有一個 SID。審查暫存檔案，依照 `install.md` 計算標準 bundle digest，並顯示 Approval receipt，內容須包含 repository、commit、digest、完整檔案清單及安裝目的地。顯示 receipt 後停止。等我核准完全相同的 receipt 後，不得重新下載；只能複製同一批暫存位元組，並確認暫存與安裝後的 digest 都等於已核准的 digest。任何不一致都必須拒絕安裝。不得為了安裝 Skill 而執行下載的腳本。

這個模式會把核准綁定到不可變的內容，適合高風險或受稽核環境；一般使用者不需要承擔這套額外流程。

### 手動安裝

使用 Git 用戶端或 GitHub archive endpoint，先把要安裝的版本解析成完整 commit SHA。將該 commit 的內容放入私有暫存位置，再依照 [install.md](install.md) 審查並驗證標準 bundle digest，確認後才複製檔案。請勿直接從任意、可變動的 checkout 安裝。

把已驗證的 `skills/user-model-distiller` 子目錄安裝到 Agent 信任的 Skill 目錄。Codex 一般使用：

```text
$CODEX_HOME/skills/user-model-distiller
```

若未設定 `CODEX_HOME`，請使用使用者個人目錄下的 `.codex/skills/user-model-distiller`。安裝完成後，如果系統沒有立刻發現 Skill，請重新啟動或開啟新的工作階段。

### 私有工作流程

所有輸入與輸出都應放在 repository 之外，最好使用專門的私有目錄。

以下範例使用 `python3`。在 Windows 上，如果已安裝 Python 3.10 以上版本，可使用 `py -3`；也可以提供已核准 Python 執行環境的完整路徑。若在 Codex 桌面版找不到這兩個指令，可請 Codex 尋找內建的 workspace Python。

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

`preview` 指令不會核准或編譯任何規則。請維持已驗證產物不可變，並把審查與核准後的版本寫入另一個私有目錄。`add-candidate` 只接受已明確審查、直接來自使用者的證據；`approve` 則要求提供使用者實際看過之候選偏好的 digest。具有限定範圍的規則，只有在執行時提供相符的專案、任務或暫時情境才會被編譯。

外部審查資料包是選用功能。它只包含隨機 review ID、證據種類與使用者文字。任何隱私警告——包括獨立出現的網域或使用 Unicode 分隔符的網域——都會阻止發布。來源 ID 對照表必須寫入另一個、具有獨立存取控制的上層目錄；如果該目錄不存在，工具會建立僅限擁有者存取的目錄。如果既有目錄可共用或繼承了過寬的權限，工具會拒絕使用。即使資料包通過檢查，在揭露給託管式審查者之前仍需取得另一個明確的使用者決定。

### 安全模型

匯入的對話內容一律視為不受信任。只有使用者本人撰寫的內容可以成為偏好候選證據，而且只有使用者明確核准後才能啟用。編譯後的執行階段提示不會包含來源引文，以降低持續性 prompt injection 的風險。

在使用真實對話紀錄前，請先閱讀 [SECURITY.md](SECURITY.md)、[威脅模型](docs/threat-model.md)，以及 Skill 的[安全與隱私政策](skills/user-model-distiller/references/security-and-privacy.md)。

### 開發

執行階段腳本只使用 Python 標準函式庫，支援 Python 3.10 以上版本。

```bash
python3 -m unittest discover -s tests -v
python3 tools/check_repository.py
python3 -m compileall -q skills tests tools
```

請在 repository 之外建立可重現的 release，並在建立 tag 前驗證：

```bash
python3 tools/build_release.py build --output-dir /private/release-0.2.3 \
  --expected-tag v0.2.3 --source-date-epoch 0
python3 tools/build_release.py verify /private/release-0.2.3
```

release 目錄會包含 Skill ZIP、SPDX 2.3 SBOM、`SHA256SUMS` 與封閉格式的 manifest。推送 tag 時會執行同一套測試，且只發布經驗證的產物。在首次公開發布前，repository 管理員應套用並確認 [GitHub 強化設定](docs/github-hardening.md)。

Issue、pull request、測試或範例都不接受真實 session 資料；請使用最小化的合成測試資料。

### 狀態與限制

- 上游匯出格式演進時，匯入格式也可能需要調整。
- 證據偵測支援多語言，但仍採啟發式判斷。來源封裝、引文、否定語句、簡短修正與複合子句仍是必要的評估案例。
- 高隱私模式只是在降低再識別風險，無法保證匿名。語意中的組織、專案、人際關係與第三方情境可能在字面遮蔽後仍然存在；外部審查閘門會在偵測到這些警告時阻擋發布。
- 模型輔助審查永遠不會自動啟用。託管式審查需要獨立的揭露核准、只含使用者資料的最小欄位資料包、通過外部審查隱私報告，以及使用者明確同意。
- 高品質整合仍需要模型輔助審查或人工編輯。
- 若要持續跨 session 同步，需要另外取得授權的 connector 或應用程式；單靠 Skill 不會取得帳號存取權。

### 授權

採用 Apache License 2.0，詳見 [LICENSE](LICENSE)。

---

## English

A local-first Codex Skill that turns authorized chat histories into a reviewable, evidence-backed model of how a user prefers to work.

The project is designed to reduce repeated correction without silently profiling the user. Candidate preferences do not become active until the user reviews them.

> Alpha software. Use synthetic or backed-up data while evaluating it.

### What it does

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

### What it does not do

- It does not log in to, scrape, or bypass access controls on ChatGPT.
- It does not automatically read every account conversation.
- It does not upload histories to a memory service.
- It does not treat model or tool output as truth about the user.
- It does not infer protected traits or create a psychological profile.
- It does not modify ChatGPT Memory or Codex memory files without an explicit request.

### Quick install (recommended)

Most Codex desktop, CLI, and IDE users can give their agent this instruction:

> Use `$skill-installer` to install `user-model-distiller` from `https://github.com/jacky-0218-lung/user-model-distiller/tree/9afdd7b5d09361ddebe09918c6f8aaae897964b0/skills/user-model-distiller`. Prefer direct download for this public repository and fall back to Git only if direct download is unavailable because of authentication or permission errors. Do not execute downloaded Skill scripts during installation. If the destination already exists, stop and report it instead of overwriting it. After installation, report the installed path and tell me when the Skill is available.

The source is pinned to the full commit SHA for `v0.2.3`, so later changes to `main` cannot change the installed bytes. The built-in installer prefers direct download, which normally avoids a staging Git repository, custom Windows ACLs, and `safe.directory` configuration. The Skill is available on the next turn; restart Codex if it does not appear.

### High-assurance install (optional)

For environments that require per-file review, a reproducible digest, and an approval receipt, give your agent this instruction:

> Resolve the default branch of `jacky-0218-lung/user-model-distiller` exactly once to a full 40-character commit SHA. Prefer one direct HTTPS archive download for that commit; do not create a Git repository only for staging. If Git is required, use the same operating-system identity for every `.git` operation. Extract only `install.md` and the complete `skills/user-model-distiller` subtree into a new private staging directory. On Windows, preserve access for both the Codex sandbox and approved host identities required by the installation; do not assume a single SID. Review every staged file, calculate the canonical bundle digest defined in `install.md`, and show me an Approval receipt containing the repository, commit, digest, complete file list, and destination. Stop after showing the receipt. After I approve that exact receipt, do not re-fetch; copy only the same staged bytes, verify that the staging and installed digests both match the approved digest, and refuse installation on any mismatch. Do not execute downloaded scripts merely to install the Skill.

This mode binds approval to immutable content and is intended for high-risk or audited environments. Most users do not need the additional workflow.

### Manual install

Use a Git client or GitHub's archive endpoint to resolve the version you want to a full commit SHA, stage the exact commit privately, and follow [install.md](install.md) to review and verify its canonical bundle digest before copying anything. Do not copy from an arbitrary mutable checkout.

Install the verified `skills/user-model-distiller` subtree into your agent's trusted Skill directory. For Codex this is normally:

```text
$CODEX_HOME/skills/user-model-distiller
```

When `CODEX_HOME` is unset, use the `.codex/skills/user-model-distiller` directory under your user profile. Restart or open a new task after installation if the Skill is not discovered immediately.

### Private workflow

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

### Security model

Imported transcripts are untrusted. Only user-authored evidence may become a preference candidate, and only explicit user approval may activate it. Source quotes are kept out of the compiled runtime prompt to reduce persistent prompt-injection risk.

See [SECURITY.md](SECURITY.md), the [threat model](docs/threat-model.md), and the Skill's [security policy](skills/user-model-distiller/references/security-and-privacy.md) before using real histories.

### Development

The runtime scripts use only the Python standard library and support Python 3.10 or later.

```bash
python3 -m unittest discover -s tests -v
python3 tools/check_repository.py
python3 -m compileall -q skills tests tools
```

Build a deterministic release outside the repository and verify it before tagging:

```bash
python3 tools/build_release.py build --output-dir /private/release-0.2.3 \
  --expected-tag v0.2.3 --source-date-epoch 0
python3 tools/build_release.py verify /private/release-0.2.3
```

The release directory contains the Skill ZIP, an SPDX 2.3 SBOM, `SHA256SUMS`, and a closed manifest. Tag pushes run the same tests and publish only these verified artifacts. Repository administrators should apply and verify the settings in [GitHub hardening](docs/github-hardening.md) before the first public release.

Real session data is not accepted in issues, pull requests, tests, or examples. Use minimal synthetic fixtures.

### Status and limitations

- Import formats can change as upstream export schemas evolve.
- Evidence detection is multilingual but heuristic. Provenance envelopes, quotations, negation, terse corrections, and compound clauses remain mandatory evaluation slices.
- High privacy is de-identification risk reduction, not guaranteed anonymity. Semantic organization, project, relationship, and third-party context can survive lexical masking; the external-review gate blocks on these warnings.
- Model-assisted review is never automatic. Hosted review requires a separate disclosure, a user-only minimum-field pack, a passing external-review privacy report, and user approval.
- High-quality consolidation still requires model-assisted review or manual editing.
- Continuous cross-session synchronization requires a separately authorized connector or application; a Skill alone does not grant account access.

### License

Apache License 2.0. See [LICENSE](LICENSE).
