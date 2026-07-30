# Changelog

本檔記錄各版本之間對使用者可見的變更，特別是會改變既有輸出的行為變更。版本號採語意化版本，`pyproject.toml` 的 `version` 為單一真實來源，release tag 必須為 `v<version>`。

This file records user-visible changes between releases, with emphasis on behaviour changes that alter existing output. `pyproject.toml` holds the single source of truth for the version; a release tag must be `v<version>`.

## 0.3.0

### 行為變更（升級前請閱讀）

- **正規化器會剝除隱形字元。** `normalize_sessions.py`（內部版本 0.4.0）在遮蔽之前移除 Unicode Tag 區塊、bidi 覆寫與隔離控制、零寬空白、BOM、interlinear annotation 控制、soft hyphen，以及 tab／newline 以外的 C0/C1 控制字元，並把 `\r\n`／`\r` 正規化為 `\n`。移除數量計入既有的 `redaction_count`，不新增欄位。
  - **影響**：同一份輸入在 0.3.0 產出的 `normalized.jsonl` 內容與 `redaction_count` 會與 0.2.x 不同。既有的 run 目錄不會失效（`verify` 仍以其自身 manifest 為準），但**跨版本比對 digest 會不相等**，屬預期結果。
  - **理由**：本專案的安全性建立在「使用者審查他所看到的內容」之上。審查畫面看不到、模型卻讀得到的字元使這個前提失效，並可用來把 secret 切開以規避遮蔽。
- **隱私閘門新增 blocker `deceptive_invisible_characters`。** 已正規化的檔案不可能含這些字元，若存在即代表該檔案是手工產生或事後被改動，一律阻擋。新增 warning `zero_width_joiner`；U+200C／U+200D 為波斯語、阿拉伯語、印度系文字與 emoji 序列所必需，故保留但提出警告，並在 `external-review` 模式升級為阻擋。
- **`tools/skill_bundle.py` receipt schema 1.0 → 1.1。** receipt 新增 `invisible_character_scan` 欄位；掃描到隱形字元時**不會產生 receipt**。舊版 receipt 仍可用 `verify` 比對 digest，但不含此聲明。

### 新增

- CI 守門（`tools/check_repository.py`）阻擋追蹤檔案中的隱形與 bidi 控制字元，避免本 repo 自身把隱形指令發佈給安裝者。
- `references/profile-schema.md` 新增「Temporal semantics」一節，明確定義四個時間欄位、`--as-of` 的作用範圍與限制，以及如何由 supersedes 鏈還原某時點適用的規則。
- README 新增中英雙語「疑難排解」段落。

### 變更

- `SKILL.md` 第 8 節補上確定性的規則挑選指引（先 scope、後 category，不只依語意相似度）。
- README 補充 Skill 安裝目錄上游不一致（`.codex/skills` 與 `.agents/skills`）時的排除說明。
- CI 相依：`actions/checkout` 4.3.1 → 7.0.1、`github/codeql-action` 4.37.1 → 4.37.3（init 與 analyze 一併升級以維持版本一致）。

### 已知限制

- 編譯支援 `expires_at`，但目前沒有任何指令會設定它；需要有效期限的偏好請改用 `temporary` scope。

## 0.2.3

跨平台正規化 release 文字位元組，使可重現建置在不同平台產生相同產物。

## 0.2.2

修正 release 發布流程的 repository context。

## 0.2.1

修正 release 的 annotated tag 驗證。

## 0.2.0

首個安全基線版本。
