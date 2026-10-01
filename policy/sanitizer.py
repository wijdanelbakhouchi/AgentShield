import re
from typing import List, Tuple


class InputSanitizer:
    """
    Input Sanitizer (Phase 3):
    Performs automated sanitization on high-risk input payloads before agent execution:
    - Redacts API keys and secret credentials
    - Strips prompt injection phrases and override vectors
    - Neutralizes hazardous code execution syntax and script tags
    """

    REDACT_PATTERNS: List[Tuple[str, str]] = [
        (r"sk-[a-zA-Z0-9]{20,}", "[REDACTED_OPENAI_KEY]"),
        (r"AIzaSy[a-zA-Z0-9_-]{33}", "[REDACTED_GEMINI_KEY]"),
        (r"AKIA[0-9A-Z]{16}", "[REDACTED_AWS_KEY]"),
        (r"gsk_[a-zA-Z0-9]{20,}", "[REDACTED_GROQ_KEY]"),
    ]

    STRIP_INJECTION_PATTERNS: List[Tuple[str, str]] = [
        (
            r"ignore\s+(all\s+)?(previous|prior)\s+(instructions|prompts|directions)",
            "[REDACTED_INJECTION_OVERRIDE]",
        ),
        (r"system\s+(override|bypass|disable)", "[REDACTED_SYSTEM_OVERRIDE]"),
        (
            r"jailbreak|you\s+are\s+now\s+dan|do\s+anything\s+now",
            "[REDACTED_JAILBREAK_ATTEMPT]",
        ),
        (
            r"disregard\s+(your\s+)?(rules|safety|constraints|guidelines)",
            "[REDACTED_SAFETY_BYPASS]",
        ),
    ]

    NEUTRALIZE_CODE_PATTERNS: List[Tuple[str, str]] = [
        (r"\beval\s*\(", "sanitized_eval("),
        (r"\bexec\s*\(", "sanitized_exec("),
        (r"rm\s+-rf", "sanitized_rm_rf"),
        (r"<script.*?>.*?</script>", "[REDACTED_SCRIPT_TAG]"),
    ]

    @classmethod
    def sanitize(cls, text: str) -> str:
        """
        Sanitizes text by redacting credentials, stripping injections, and neutralizing code.
        """
        if not text:
            return ""

        sanitized = text

        # 1. Redact Secret API Keys
        for pattern, replacement in cls.REDACT_PATTERNS:
            sanitized = re.sub(pattern, replacement, sanitized)

        # 2. Strip Injection Overrides
        for pattern, replacement in cls.STRIP_INJECTION_PATTERNS:
            sanitized = re.sub(
                pattern, replacement, sanitized, flags=re.IGNORECASE
            )

        # 3. Neutralize Dangerous Code Execution Constructs
        for pattern, replacement in cls.NEUTRALIZE_CODE_PATTERNS:
            sanitized = re.sub(
                pattern, replacement, sanitized, flags=re.IGNORECASE
            )

        return sanitized
