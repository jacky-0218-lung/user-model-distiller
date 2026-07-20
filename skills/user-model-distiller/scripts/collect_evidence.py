#!/usr/bin/env python3
"""Create a review queue of likely user preference evidence from normalized JSONL."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tempfile
from pathlib import Path
from typing import Any, Iterable


MAX_INPUT_BYTES = 256 * 1024 * 1024
VERSION = "0.2.1"
MAX_TEXT_CHARS = 4_000
MAX_RECORDS = 1_000_000
MAX_MIXED_ENVELOPE_CHARS = 4_000

QUOTED_SPAN_RE = re.compile(
    r'''(?:"[^"\n]*"|“[^”\n]*”|‘[^’\n]*’|'[^'\n]*'|「[^」\n]*」|『[^』\n]*』)'''
)
FENCED_BLOCK_RE = re.compile(r"(?ms)^\s*```.*?^\s*```\s*$")
UNTRUSTED_XML_RE = re.compile(
    r"(?is)<(?:system|developer|assistant|tool|tool_result|environment_context|permissions(?:_instructions)?|recommended_plugins)\b[^>]*>.*?</(?:system|developer|assistant|tool|tool_result|environment_context|permissions(?:_instructions)?|recommended_plugins)>"
)
BLOCKQUOTE_RE = re.compile(r"(?m)^\s*>.*(?:\n|$)")
ROLE_LINE_RE = re.compile(r"(?im)^\s*(?:system|developer|assistant|tool|tool result|user)\s*:\s*")
JSON_TRANSCRIPT_RE = re.compile(r'(?is)^\s*[\[{].{0,4000}"role"\s*:\s*"(?:assistant|tool|system|developer)"')
CLAUSE_SPLIT_RE = re.compile(r"[。！？!?；;\n]+")
EPISODIC_LIMITER_RE = re.compile(
    r"(?:\b(?:for (?:only )?this (?:answer|response|request|task|event|message)|"
    r"this time|today(?: only)?|for the current (?:answer|request|task|event)|"
    r"for this [^.?!\n]{0,80}\bonly)\b|"
    r"(?:這次|這一題|這個回答|本次|今天(?:只)?)|"
    r"(?:今回|この回答|この質問|今日(?:だけ)?)|"
    r"\b(?:esta vez|esta respuesta|esta tarea|hoy(?: solamente)?)\b)",
    re.I,
)

CUES: dict[str, tuple[re.Pattern[str], ...]] = {
    "explicit_preference": (
        re.compile(
            r"(?:我(?:比較|更)?(?:喜歡|偏好|希望|習慣)|"
            r"(?:請|麻煩)(?:你)?(?:先|再|只|都|一律|務必|永遠|不要|別|避免|使用|用|以|採用|保持|引用|提供|回答|回覆|輸出|改成|改用)|"
            r"(?:從現在開始|以後|往後|之後)|(?:改成|改用|換成))"
        ),
        re.compile(
            r"\b(?:i (?:strongly )?prefer|i (?:really )?like|"
            r"(?:concise|brief|short|detailed)?\s*(?:answers?|responses?|output|bullet points?)\s+works? best for me|"
            r"from now on|going forward|when you (?:answer|respond|reply)|"
            r"could you (?:please )?(?:stick to|keep|use|write|answer|respond|reply|format|cite|include|exclude|avoid|start|lead|end|ask|show|provide|return))\b",
            re.I,
        ),
        re.compile(
            r"(?:^|[.!?]\s*)(?:please\s+)?(?:always\s+|never\s+)?"
            r"(?:make|keep|use|write|answer|respond|reply|format|cite|include|exclude|avoid|start|lead|end|ask|show|provide|return)\b",
            re.I,
        ),
        re.compile(
            r"\b(?:for all future|in (?:all )?future|for every future|across future)\s+"
            r"(?:answers?|responses?|replies?|messages?).{0,60}"
            r"(?:always|consistently|continue|keep|maintain|use|write|answer|respond|format|include|avoid)\b",
            re.I,
        ),
        re.compile(
            r"(?:今後|これから|以後|以降|常に|毎回|必ず|継続して|続けて).{0,40}"
            r"(?:してください|して下さい|使って|用いて|維持|統一|書いて|回答)",
        ),
        re.compile(
            r"(?:我(?:比较|更)?(?:喜欢|偏好|希望|习惯)|"
            r"(?:请|麻烦)(?:你)?(?:先|再|只|都|一律|务必|永远|不要|别|避免|使用|用|以|采用|保持|引用|提供|回答|回复|输出|改成|改用)|"
            r"(?:从现在开始|以后|往后|之后))"
        ),
        re.compile(
            r"\b(?:a partir de ahora|de ahora en adelante|en adelante|para futuras? respuestas?|"
            r"en todas las respuestas).{0,80}"
            r"(?:siempre|contin[uú]a|mant[eé]n|usa|utiliza|escribe|responde|incluye|evita)\b",
            re.I,
        ),
        re.compile(
            r"\b(?:for|in) future (?:conversations?|interactions?|sessions?|tasks?).{0,100}"
            r"\b(?:always|consistently|continue|keep|maintain|use|write|answer|respond|format|include|avoid|put)\b",
            re.I,
        ),
        re.compile(
            r"(?:今後|これから).{0,30}(?:やり取り|会話|回答|返答|応答).{0,100}"
            r"(?:必ず|常に|継続|続け|使ってください|してください)"
        ),
        re.compile(
            r"\bpara (?:este|el) proyecto\b.{0,180}"
            r"(?:siga vigente|durante todo el proyecto|de forma continua|siempre|mant[eé]n)",
            re.I,
        ),
    ),
    "correction": (
        re.compile(r"^\s*(?:shorter|briefer|more concise|less detail)[.!]?\s*$", re.I),
        re.compile(
            r"(?:不是(?:這樣|我要的)|不要|別再|太長|太短|改成|改為|改用|換成|替換|重新命名|"
            r"刪除|移除|新增|補上|加上|縮短|延長|重寫|重做|停止|你(?:又|一直)|少一點|多一點|"
            r"請?(?:修正|更正|修改))"
        ),
        re.compile(
            r"\b(?:not what i (?:asked|wanted)|do not|don't|too long|too short|instead|redo|rewrite|"
            r"you keep|stop doing|correct this|switch to|change (?:it )?to|rename|replace|remove|delete|"
            r"add|shorten|extend|revise|update)\b",
            re.I,
        ),
        re.compile(
            r"(?:不是(?:这样|我要的)|不要|别再|太长|太短|改成|改为|改用|换成|替换|重新命名|"
            r"删除|移除|新增|补上|加上|缩短|延长|重写|重做|停止|你(?:又|一直)|少一点|多一点|"
            r"请?(?:修正|更正|修改))"
        ),
    ),
    "approval": (
        re.compile(r"^\s*(?:這版|這樣(?:就)?(?:對|很好|可以(?:了)?)|就是這樣|很好|可以了|正確)(?:[，,。！!]|$)"),
        re.compile(r"(?:其他|其餘|剩下).{0,30}(?:這樣(?:就)?可以(?:了)?|保持不變)"),
        re.compile(r"(?:以後|往後).{0,20}(?:照這樣|這個格式|這種方式)"),
        re.compile(
            r"^\s*(?:that's right|this works|perfect|exactly|looks good)"
            r"(?:(?:,\s*(?:that's right|this works|perfect|exactly|looks good))|[.!]|$)",
            re.I,
        ),
        re.compile(r"\buse this going forward\b", re.I),
        re.compile(r"^\s*(?:这版|这样(?:就)?(?:对|很好|可以(?:了)?)|就是这样|很好|可以了|正确)(?:[，,。！!]|$)"),
        re.compile(r"(?:其他|其余|剩下).{0,30}(?:这样(?:就)?可以(?:了)?|保持不变)"),
    ),
}


class EvidenceError(ValueError):
    """Raised for unsafe or invalid evidence inputs."""


def extract_direct_user_text(text: str) -> tuple[str, list[str]]:
    """Remove common imported-data envelopes without interpreting their contents."""
    reasons: list[str] = []
    cleaned, count = FENCED_BLOCK_RE.subn(" ", text)
    if count:
        reasons.append("fenced_block")
    cleaned, count = UNTRUSTED_XML_RE.subn(" ", cleaned)
    if count:
        reasons.append("untrusted_xml")
    cleaned, count = BLOCKQUOTE_RE.subn(" ", cleaned)
    if count:
        reasons.append("blockquote")
    role_lines = list(ROLE_LINE_RE.finditer(cleaned))
    if len(role_lines) >= 2 or any(
        match.group(0).strip().lower().startswith(("system", "developer", "assistant", "tool"))
        for match in role_lines
    ):
        cleaned = cleaned[: role_lines[0].start()]
        reasons.append("role_transcript")
    if JSON_TRANSCRIPT_RE.search(cleaned):
        cleaned = ""
        reasons.append("json_transcript")
    cleaned = QUOTED_SPAN_RE.sub(" ", cleaned)
    return "\n".join(line.rstrip() for line in cleaned.splitlines()).strip(), reasons


def score_text(text: str, *, has_assistant_context: bool = False) -> tuple[int, list[str]]:
    searchable = text
    kinds: list[str] = []
    score = 0
    for kind, patterns in CUES.items():
        if kind == "approval" and not has_assistant_context and not re.search(
            r"(?:以後|往後|going forward|from now on)", searchable, re.I
        ):
            continue
        if any(pattern.search(searchable) for pattern in patterns):
            kinds.append(kind)
            score += {"explicit_preference": 2, "correction": 3, "approval": 2}[kind]
    for clause in (part.strip() for part in CLAUSE_SPLIT_RE.split(searchable)):
        if not clause:
            continue
        for kind, patterns in CUES.items():
            if kind == "approval" and not has_assistant_context:
                continue
            if kind not in kinds and any(pattern.search(clause) for pattern in patterns):
                kinds.append(kind)
                score += {"explicit_preference": 2, "correction": 3, "approval": 2}[kind]
    if len(text) <= 240:
        score += 1
    if "?" in text or "？" in text:
        score = max(0, score - 1)
    return score, kinds


def read_records(path: Path) -> list[dict[str, Any]]:
    if path.is_symlink():
        raise EvidenceError(f"Refusing symbolic link input: {path}")
    if not path.is_file():
        raise EvidenceError(f"Input does not exist: {path}")
    if path.stat().st_size > MAX_INPUT_BYTES:
        raise EvidenceError("Input exceeds size limit")
    records: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8-sig") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise EvidenceError(f"Invalid JSON at line {line_number}: {exc.msg}") from exc
            if not isinstance(record, dict):
                raise EvidenceError(f"Line {line_number} is not an object")
            role = record.get("role")
            if role not in {"user", "assistant"}:
                raise EvidenceError(f"Unexpected role at line {line_number}: {role!r}")
            if not isinstance(record.get("text"), str):
                raise EvidenceError(f"Missing text at line {line_number}")
            if len(records) >= MAX_RECORDS:
                raise EvidenceError("Input exceeds record limit")
            records.append(record)
    return records


def build_evidence(records: list[dict[str, Any]], min_score: int, per_session: int) -> Iterable[dict[str, Any]]:
    previous_by_session: dict[str, dict[str, Any]] = {}
    counts: dict[str, int] = {}
    for record in records:
        session_id = str(record.get("session_id", ""))
        if record["role"] == "assistant":
            previous_by_session[session_id] = record
            continue
        direct_text, suppression_reasons = extract_direct_user_text(record["text"])
        if not direct_text:
            continue
        # Large messages that mix direct prose with quoted, fenced, or role-labelled
        # history are review packages, not reliably attributable user statements.
        # Fail closed instead of scoring the surviving meta commentary.
        if suppression_reasons and len(record["text"]) > MAX_MIXED_ENVELOPE_CHARS:
            continue
        context = previous_by_session.get(session_id)
        score, kinds = score_text(direct_text, has_assistant_context=context is not None)
        if EPISODIC_LIMITER_RE.search(direct_text) and "explicit_preference" in kinds:
            kinds = [kind for kind in kinds if kind != "explicit_preference"]
            score = max(0, score - 2)
        if score < min_score or not kinds:
            continue
        if counts.get(session_id, 0) >= per_session:
            continue
        counts[session_id] = counts.get(session_id, 0) + 1
        truncated = len(direct_text) > MAX_TEXT_CHARS
        yield {
            "schema_version": "1.0",
            "session_id": session_id,
            "message_id": str(record.get("message_id", "")),
            "created_at": record.get("created_at"),
            "score": score,
            "kinds": kinds,
            "user_text": direct_text[:MAX_TEXT_CHARS],
            "context_message_id": str(context.get("message_id", "")) if context else None,
            "source": record.get("source"),
            "provenance": {
                "role": "user",
                "direct": True,
                "suppressed_envelopes": suppression_reasons,
            },
            "truncated": truncated,
            "review_status": "needs_full_review" if truncated else "unreviewed",
            "notice": "Candidate evidence only. Do not activate without user review.",
        }


def atomic_write(path: Path, rows: Iterable[dict[str, Any]], overwrite: bool) -> int:
    if path.exists() and not overwrite:
        raise EvidenceError(f"Output exists; pass --overwrite to replace it: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_name = ""
    count = 0
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", newline="\n", delete=False, dir=path.parent,
            prefix=f".{path.name}.", suffix=".tmp"
        ) as handle:
            temp_name = handle.name
            for row in rows:
                handle.write(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n")
                count += 1
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, path)
        try:
            path.chmod(0o600)
        except OSError:
            pass
        return count
    finally:
        if temp_name and os.path.exists(temp_name):
            try:
                os.unlink(temp_name)
            except OSError:
                pass


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="Normalized JSONL from normalize_sessions.py")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--min-score", type=int, default=2)
    parser.add_argument("--per-session", type=int, default=100)
    parser.add_argument("--overwrite", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.min_score < 1 or args.per_session < 1:
        print("error: --min-score and --per-session must be positive", file=sys.stderr)
        return 2
    try:
        records = read_records(args.input.resolve())
        count = atomic_write(
            args.output.resolve(), build_evidence(records, args.min_score, args.per_session), args.overwrite
        )
    except (OSError, EvidenceError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({"candidates": count, "output": str(args.output)}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
