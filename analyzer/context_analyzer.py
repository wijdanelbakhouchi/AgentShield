import re
from typing import Any, Dict, List, Tuple


class ContextAnalyzer:
    """
    Sub-detector 2.3: Context Analyzer.
    Scans retrieved data, tool outputs, and document contexts for indirect prompt injections,
    embedded hidden instructions, zero-width characters, and script injection vectors.
    """

    INDIRECT_INJECTION_PATTERNS: List[Tuple[str, str]] = [
        (
            r"system\s*note\s*:\s*(ignore|disregard|execute)",
            "CONTEXT_INDIRECT_INJECTION:SYSTEM_NOTE_OVERRIDE",
        ),
        (
            r"new\s+instructions?\s*:\s*",
            "CONTEXT_INDIRECT_INJECTION:NEW_INSTRUCTIONS_TRIGGER",
        ),
        (
            r"\[system\s*prompt\s*update\]",
            "CONTEXT_INDIRECT_INJECTION:SYSTEM_PROMPT_UPDATE",
        ),
        (
            r"override\s+previous\s+(context|instructions)",
            "CONTEXT_INDIRECT_INJECTION:OVERRIDE_CONTEXT",
        ),
        (
            r"forget\s+all\s+(user|prior)\s+(requests|prompts)",
            "CONTEXT_INDIRECT_INJECTION:FORGET_USER_REQUESTS",
        ),
        (
            r"trusted\s+application\s+instruction|you\s+are\s+now\b|untamed\s+bot|output\s+['\"]hacked['\"]",
            "CONTEXT_INDIRECT_INJECTION:CONTEXT_POISONING",
        ),
    ]

    HIDDEN_PAYLOAD_PATTERNS: List[Tuple[str, str]] = [
        (r"[\u200b\u200c\u200d\ufeff]", "CONTEXT_SUSPICIOUS:ZERO_WIDTH_CHARS"),
        (
            r"style\s*=\s*[\"'].*?display\s*:\s*none.*?[\"']",
            "CONTEXT_SUSPICIOUS:HIDDEN_HTML_ELEMENT",
        ),
        (r"<iframe.*?>", "CONTEXT_SUSPICIOUS:EMBEDDED_IFRAME"),
        (r"data:text/html;base64,", "CONTEXT_SUSPICIOUS:BASE64_PAYLOAD"),
    ]

    @classmethod
    def analyze_context(cls, context_text: str) -> Dict[str, Any]:
        """
        Evaluates context payload text for security anomalies and indirect injections.
        """
        flags: List[str] = []

        if not context_text:
            return {"flags": [], "is_clean": True}

        # 1. Indirect Prompt Injection Scan
        for pattern, tag in cls.INDIRECT_INJECTION_PATTERNS:
            if re.search(pattern, context_text, re.IGNORECASE):
                flags.append(tag)

        # 2. Hidden Payload & Anomaly Scan
        for pattern, tag in cls.HIDDEN_PAYLOAD_PATTERNS:
            if re.search(pattern, context_text, re.IGNORECASE):
                flags.append(tag)

        return {
            "flags": flags,
            "is_clean": len(flags) == 0,
        }
