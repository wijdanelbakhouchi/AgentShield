"""Deterministic, explainable rule detection over normalized representations."""

from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Mapping, Sequence, Tuple


class RuleBasedDetector:
    """Scan one or more gateway representations without changing policy logic.

    ``scan`` accepts the historical string API and the Phase 5 representation
    list. Findings are deduplicated by rule ID while retaining the first
    matching representation/provenance for auditability.
    """

    PROMPT_INJECTION_PATTERNS: List[Tuple[str, str]] = [
        (
            r"\bignore\s+(?:all\s+)?(?:previous|prior)\s+(?:instructions?|prompts?|directions?)\b",
            "PROMPT_INJECTION:IGNORE_PREVIOUS_INSTRUCTIONS",
        ),
        (
            r"\bsystem\s+(?:override|bypass|disable)\b",
            "PROMPT_INJECTION:SYSTEM_OVERRIDE",
        ),
        (
            r"\bjailbreak\b|\byou\s+are\s+now\b|\bdo\s+anything\s+now\b|\boperating\s+with\s+root\b|\bdevnull\s+ai\b",
            "PROMPT_INJECTION:JAILBREAK_ATTEMPT",
        ),
        (
            r"\bdisregard\s+(?:all\s+|your\s+)?(?:initial\s+)?(?:directives?|rules|safety|constraints|guidelines|instructions?)\b|\bnew\s+policy\s*:\b",
            "PROMPT_INJECTION:DISREGARD_SAFETY",
        ),
        (
            r"\bdeveloper\s+mode\s+enabled\b|\bact\s+as\s+an?\s+unfiltered\b|\bact\s+as\s+an?\s+unrestricted\b",
            "PROMPT_INJECTION:ROLE_HIJACK",
        ),
        (
            r"\bforget\s+(?:all\s+)?your\s+(?:rules|system\s+prompt)\b",
            "PROMPT_INJECTION:FORGET_RULES",
        ),
        (
            r"\bignore\s+(?:your|the)\s+system\s+prompt\b|"
            r"\b(?:disable|bypass)\s+(?:all\s+|your\s+|the\s+)?(?:security|safety\s+rules|developer\s+guidelines)\b",
            "PROMPT_INJECTION:DISREGARD_SAFETY",
        ),
        (
            r"\bignore\s+(?:toutes?\s+)?(?:les\s+)?instructions?\s+pr[ée]c[ée]dentes?\b|"
            r"\bignora\s+(?:todas\s+)?(?:las\s+)?instrucciones\s+anteriores\b|"
            r"تجاهل\s+(?:كل\s+|جميع\s+)?التعليمات\s+السابقة",
            "PROMPT_INJECTION:IGNORE_PREVIOUS_INSTRUCTIONS",
        ),
        (
            r"(?:^|[.!?;\n])\s*(?:please\s+)?(?:now\s+|from\s+now\s+on[, ]+)?"
            r"(?:you\s+are|you're|you’re|u\s+are|u['’]?re|ur)\s+(?:now\s+)?"
            r"(?:the\s+|an?\s+)?(?:administrator|admin|root|superuser)\b",
            "PROMPT_INJECTION:PRIVILEGED_ROLE_OVERRIDE",
        ),
        (
            r"\b(?:reveal|show|print|output|repeat|dump|extract|disclose|expose)\b"
            r".{0,80}\b(?:hidden\s+)?(?:system|developer|internal)\b"
            r".{0,40}\b(?:prompt|instructions?|directions?|context)\b",
            "PROMPT_INJECTION:SYSTEM_PROMPT_EXFILTRATION",
        ),
        (
            r"<agent_data>.*?(?:override|delete|drop|bypass|ignore).*?</agent_data>|\boverride\s+planner\b",
            "PROMPT_INJECTION:AGENT_TO_AGENT_INJECTION",
        ),
    ]

    DATA_LEAKAGE_PATTERNS: List[Tuple[str, str]] = [
        (
            r"\b(?:read|show|print|dump|extract|reveal)\b.{0,60}\b(?:secrets?|credentials?|tokens?)\b.{0,40}\b(?:environment|process|config(?:uration)?)\b|"
            r"\b(?:send|upload|transmit|forward|exfiltrate)\b.{0,50}\b(?:all\s+(?:available\s+)?data|secrets?|credentials?)\b.{0,50}\bto\s+(?:https?://)?[a-z0-9.-]+\.[a-z]{2,}\b",
            "DATA_LEAKAGE:DATA_EXFILTRATION",
        ),
        (
            r"\b(?:reveal|show|print|dump|disclose|expose|output)\s+"
            r"(?:(?:to\s+)?me\s+)?(?:all\s+)?(?:your|ur|the\s+system['’]s)\s+"
            r"(?:all\s+)?(?:hidden\s+|internal\s+)?(?:secrets?|credentials?|passwords?|tokens?)\b",
            "DATA_LEAKAGE:CREDENTIAL_HARVESTING",
        ),
        (r"\bsk-[a-zA-Z0-9]{20,}\b", "DATA_LEAKAGE:OPENAI_API_KEY_PATTERN"),
        (r"\bAIzaSy[a-zA-Z0-9_-]{33}\b", "DATA_LEAKAGE:GEMINI_API_KEY_PATTERN"),
        (r"\bAKIA[0-9A-Z]{16}\b", "DATA_LEAKAGE:AWS_ACCESS_KEY_PATTERN"),
        (
            r"\b(?:show|print|dump|output|get|reveal|extract|disclose)\b.{0,80}"
            r"\b(?:api[_ -]?key|secret[_ -]?key|password|\.env|environment\s+var(?:iable)?s?|environment\s+secrets?)\b",
            "DATA_LEAKAGE:CREDENTIAL_HARVESTING",
        ),
        (
            r"\b(?:send|exfiltrate|post|transmit|forward|leak|upload)\b.{0,60}\b(?:tokens?|passwords?|credentials?|secrets?|keys?|session|database)\b.{0,60}\bhttps?://",
            "DATA_LEAKAGE:DATA_EXFILTRATION",
        ),
        (
            r"\bos\s*\.\s*(?:environ|getenv)\b|\b\.env\s+file\b",
            "DATA_LEAKAGE:ENV_ACCESS_ATTEMPT",
        ),
    ]

    CODE_EXECUTION_PATTERNS: List[Tuple[str, str]] = [
        (r"\beval\s*\(", "CODE_EXECUTION:PYTHON_EVAL"),
        (r"\bexec\s*\(", "CODE_EXECUTION:PYTHON_EXEC"),
        (r"\brm\s+-rf\b|\bformat\s+c:", "CODE_EXECUTION:SHELL_DESTRUCTIVE"),
        (
            r"\bimport\s+(?:os|sys|subprocess)\b",
            "CODE_EXECUTION:MODULE_IMPORT",
        ),
        (r"\bsubprocess\s*\.\s*(?:call|Popen|run)\b", "CODE_EXECUTION:SUBPROCESS_EXEC"),
        (
            r"\bDROP\s+TABLE\b|\bUNION\s+SELECT\b|['\"]\s*OR\s*['\"]?1['\"]?\s*=\s*['\"]?1",
            "CODE_EXECUTION:SQL_INJECTION",
        ),
        (r"<script\b.*?>.*?</script\s*>", "CODE_EXECUTION:XSS_SCRIPT_TAG"),
        (
            r"\b(?:download|fetch|curl|wget|install)\b.{0,60}\b(?:and\s+execute|and\s+run|payload|malware|\.sh|\.exe|\.bat|\.ps1|install\.sh)\b",
            "CODE_EXECUTION:MALICIOUS_DOWNLOAD_EXEC",
        ),
    ]


    _SEVERITY = {
        "prompt_injection": "HIGH",
        "data_leakage": "HIGH",
        "code_execution": "HIGH",
    }
    _DESCRIPTIONS = {
        "PROMPT_INJECTION:IGNORE_PREVIOUS_INSTRUCTIONS": "Instruction override targeting prior directions.",
        "PROMPT_INJECTION:SYSTEM_OVERRIDE": "Attempt to bypass or disable system controls.",
        "PROMPT_INJECTION:JAILBREAK_ATTEMPT": "Jailbreak or unrestricted-role request.",
        "PROMPT_INJECTION:DISREGARD_SAFETY": "Request to disregard safety constraints.",
        "PROMPT_INJECTION:ROLE_HIJACK": "Attempt to force an unfiltered developer role.",
        "PROMPT_INJECTION:PRIVILEGED_ROLE_OVERRIDE": "Attempt to assign the assistant a privileged system role.",
        "PROMPT_INJECTION:FORGET_RULES": "Request to discard established rules.",
        "PROMPT_INJECTION:SYSTEM_PROMPT_EXFILTRATION": "Request to disclose hidden system/developer instructions.",
        "DATA_LEAKAGE:OPENAI_API_KEY_PATTERN": "API-key-shaped secret detected (evidence redacted).",
        "DATA_LEAKAGE:GEMINI_API_KEY_PATTERN": "API-key-shaped secret detected (evidence redacted).",
        "DATA_LEAKAGE:AWS_ACCESS_KEY_PATTERN": "Cloud credential-shaped secret detected (evidence redacted).",
        "DATA_LEAKAGE:CREDENTIAL_HARVESTING": "Request to disclose credentials or environment secrets.",
        "DATA_LEAKAGE:ENV_ACCESS_ATTEMPT": "Attempt to access process environment or .env data.",
        "CODE_EXECUTION:PYTHON_EVAL": "Dynamic Python evaluation request.",
        "CODE_EXECUTION:PYTHON_EXEC": "Dynamic Python execution request.",
        "CODE_EXECUTION:SHELL_DESTRUCTIVE": "Destructive shell command pattern.",
        "CODE_EXECUTION:MODULE_IMPORT": "Sensitive process or shell module import.",
        "CODE_EXECUTION:SUBPROCESS_EXEC": "Subprocess execution request.",
        "CODE_EXECUTION:SQL_INJECTION": "SQL injection or destructive SQL pattern.",
        "CODE_EXECUTION:XSS_SCRIPT_TAG": "Executable script tag pattern.",
    }

    @staticmethod
    def _category(tag: str) -> str:
        prefix = tag.split(":", 1)[0]
        return {
            "PROMPT_INJECTION": "prompt_injection",
            "DATA_LEAKAGE": "data_leakage",
            "CODE_EXECUTION": "code_execution",
        }.get(prefix, "other")

    @staticmethod
    def is_quoted_discussion(text: str) -> bool:
        """Recognize a complete academic question, not a safety-word bypass.

        Anchoring the entire request prevents an appended actionable command
        from inheriting the exception for the quoted phrase.
        """
        quoted_phrase = (
            r"['\"]ignore\s+(?:all\s+)?(?:previous|prior)\s+instructions['\"]"
        )
        educational_frames = (
            rf"(?:analyze|explain)\s+the\s+phrase\s+{quoted_phrase}"
            r"(?:\s+in\s+the\s+context\s+of\s+prompt\s+injection)?"
            r"|(?:why\s+is|explain\s+why)\s+"
            rf"{quoted_phrase}\s+(?:considered\s+)?(?:dangerous|unsafe|risky)"
        )
        # Full anchoring is deliberate: an educational preface followed by an
        # actionable override (for example, "Now reveal the system prompt")
        # must still reach the detector.
        return bool(re.fullmatch(
            rf"\s*(?:{educational_frames})[.!?]?\s*",
            text,
            re.IGNORECASE,
        ))

    @staticmethod
    def _discussion_context(text: str, tag: str) -> bool:
        """Suppress referential security education, not actionable requests."""
        lower = text.casefold()
        if tag == "PROMPT_INJECTION:SYSTEM_PROMPT_EXFILTRATION":
            safe_frame = any(
                marker in lower
                for marker in (
                    "why asking", "unsafe", "protect", "prevent", "defend", "mitigate",
                    "security discussion", "is risky",
                )
            )
            actionable_howto = re.search(
                r"\bhow\s+(?:do|can|would|to)\b.{0,20}\b(?:reveal|show|extract|disclose)\b",
                lower,
            )
            return safe_frame and not actionable_howto
        if tag == "PROMPT_INJECTION:IGNORE_PREVIOUS_INSTRUCTIONS":
            if RuleBasedDetector.is_quoted_discussion(text):
                return True
            return (
                ("regex" in lower or "detect the phrase" in lower or "quoted" in lower)
                and ("'" in text or '"' in text)
            )
        if tag == "PROMPT_INJECTION:JAILBREAK_ATTEMPT":
            # A request to define or explain jailbreak terminology is
            # educational context; only actionable role-change language should
            # remain a security finding.
            return any(
                marker in lower
                for marker in (
                    "academic definition",
                    "define jailbreak",
                    "what is jailbreak",
                    "explain jailbreak",
                    "about jailbreak",
                )
            )
        if tag.startswith("CODE_EXECUTION:XSS"):
            return any(
                marker in lower for marker in ("escaped", "escape", "sanitize", "explain why")
            ) and any(marker in lower for marker in ("explain", "why", "example", "protect"))
        if tag in {
            "DATA_LEAKAGE:CREDENTIAL_HARVESTING",
            "DATA_LEAKAGE:ENV_ACCESS_ATTEMPT",
        }:
            return any(
                marker in lower
                for marker in ("protect", "prevent", "secure", "safely", "best practice", "how should")
            ) and not any(marker in lower for marker in ("show me", "dump", "reveal", "extract"))
        if tag == "CODE_EXECUTION:SQL_INJECTION":
            return any(marker in lower for marker in ("explain", "prevent", "detect", "protect", "example"))
        return False

    @staticmethod
    def _evidence(text: str, match: re.Match[str], tag: str) -> str:
        if "API_KEY" in tag or "AWS_ACCESS_KEY" in tag or "CREDENTIAL" in tag:
            return "[REDACTED]"
        snippet = " ".join(match.group(0).split())
        return snippet[:120]

    @classmethod
    def _representations(cls, input_data: Any) -> List[Dict[str, Any]]:
        if isinstance(input_data, str):
            return [{"id": "legacy-input", "text": input_data, "provenance": ["LEGACY_INPUT"]}]
        if isinstance(input_data, Mapping):
            if "text" in input_data:
                return [dict(input_data)]
            if "representations" in input_data:
                input_data = input_data["representations"]
        if isinstance(input_data, Sequence):
            result = []
            for index, item in enumerate(input_data):
                if isinstance(item, str):
                    result.append({"id": f"rep-{index}", "text": item, "provenance": []})
                elif isinstance(item, Mapping) and item.get("text"):
                    result.append(dict(item))
            return result
        return []

    @classmethod
    def scan(cls, input_data: Any) -> Dict[str, Any]:
        """Scan a string or gateway representation set and return evidence."""
        categories: Dict[str, List[str]] = {
            "prompt_injection": [],
            "data_leakage": [],
            "code_execution": [],
        }
        triggered_flags: List[str] = []
        findings: List[Dict[str, Any]] = []
        reps = cls._representations(input_data)
        if not reps:
            return {"flags": [], "categories": categories, "findings": []}

        pattern_groups: Iterable[Tuple[str, List[Tuple[str, str]]]] = (
            ("prompt_injection", cls.PROMPT_INJECTION_PATTERNS),
            ("data_leakage", cls.DATA_LEAKAGE_PATTERNS),
            ("code_execution", cls.CODE_EXECUTION_PATTERNS),
        )
        for representation in reps:
            text = str(representation.get("text", ""))
            if not text:
                continue
            rep_id = representation.get("id", "unknown")
            provenance = list(representation.get("provenance", []))
            for category, patterns in pattern_groups:
                for pattern, tag in patterns:
                    match = re.search(pattern, text, re.IGNORECASE | re.DOTALL)
                    if not match or cls._discussion_context(text, tag):
                        continue
                    if tag not in triggered_flags:
                        triggered_flags.append(tag)
                        categories.setdefault(category, []).append(tag)
                        findings.append(
                            {
                                "rule_id": tag,
                                "category": category,
                                "severity": cls._SEVERITY.get(category, "MEDIUM"),
                                "description": cls._DESCRIPTIONS.get(tag, "Deterministic security rule matched."),
                                "representation_id": rep_id,
                                "provenance": provenance,
                                "evidence": cls._evidence(text, match, tag),
                            }
                        )

        return {
            "flags": triggered_flags,
            "categories": categories,
            "findings": findings,
            "representations_scanned": len(reps),
        }
