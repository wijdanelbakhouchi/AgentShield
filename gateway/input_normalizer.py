"""Bounded, provenance-preserving input normalization for AgentShield.

The gateway keeps the caller's raw input intact and derives a small set of
detector-oriented representations. Decoders are conservative (printable text
only), depth-limited, and count-limited so normalization cannot become an
unbounded expansion primitive.
"""

from __future__ import annotations

import base64
import codecs
import html
import re
import unicodedata
import urllib.parse
from collections import deque
from typing import Any, Dict, Iterable, List, Sequence, Tuple

from config import (
    MAX_CANDIDATES_PER_REPRESENTATION,
    MAX_DECODED_LENGTH,
    MAX_DECODE_DEPTH,
    MAX_INPUT_LENGTH,
    MAX_REPRESENTATIONS,
)


# Security-relevant invisible controls. We deliberately preserve ordinary
# Unicode letters and symbols; the original input is always retained as-is.
ZERO_WIDTH_PATTERN = re.compile(
    r"[\u061C\u180E\u200B\u200C\u200D\u200E\u200F\u202A-\u202E"
    r"\u2060-\u2064\u2066-\u2069\uFEFF\u00AD\x00-\x08\x0b\x0c\x0e-\x1f\x7f]"
)
HTML_ENTITY_PATTERN = re.compile(
    r"&(?:#(?:x[0-9a-f]+|[0-9]+)|[a-z][a-z0-9]+);", re.IGNORECASE
)
URL_ESCAPE_PATTERN = re.compile(r"%[0-9a-f]{2}", re.IGNORECASE)
BASE64_TOKEN_PATTERN = re.compile(
    r"(?<![A-Za-z0-9+/])([A-Za-z0-9+/_-]{8,}={0,2})(?![A-Za-z0-9+/=_-])"
)
ESCAPED_HEX_PATTERN = re.compile(r"(?:\\x[0-9a-f]{2}){4,}", re.IGNORECASE)
PREFIX_HEX_PATTERN = re.compile(
    r"(?<![0-9A-Fa-f])0x(?:[0-9A-Fa-f]{2}){8,}(?![0-9A-Fa-f])", re.IGNORECASE
)
RAW_HEX_PATTERN = re.compile(
    r"(?<![0-9A-Fa-f#x])(?:[0-9A-Fa-f]{2}){8,}(?![0-9A-Fa-f])",
    re.IGNORECASE,
)

# Leetspeak is intentionally scoped to mixed alphanumeric tokens. It is not
# applied to strings that are plausibly an encoded token, preserving decoder
# input (e.g. Base64's digits and raw hexadecimal).
LEET_CHAR_MAP = {
    "@": "a",
    "4": "a",
    "3": "e",
    "€": "e",
    "1": "i",
    "!": "i",
    "0": "o",
    "$": "s",
    "5": "s",
    "7": "t",
    "+": "t",
    "8": "b",
}

# A deliberately small, security-scoped confusable map. This is not a claim
# of complete Unicode confusable coverage.
CONFUSABLE_MAP = str.maketrans(
    {
        "а": "a", "А": "A", "е": "e", "Е": "E", "і": "i", "І": "I",
        "о": "o", "О": "O", "р": "p", "Р": "P", "с": "c", "С": "C",
        "х": "x", "Х": "X", "у": "y", "У": "Y", "ј": "j", "Ј": "J",
        "ο": "o", "Ο": "O", "ι": "i", "Ι": "I",
    }
)

PROVENANCE_IDS = {
    "NORMALIZED_UNICODE",
    "ZERO_WIDTH_REMOVED",
    "CONFUSABLES_NORMALIZED",
    "LEETSPEAK_NORMALIZED",
    "SPACING_NORMALIZED",
    "BASE64_DECODED",
    "HEX_DECODED",
    "ROT13_DECODED",
    "URL_DECODED",
    "HTML_ENTITY_DECODED",
}


def sanitize_unicode(text: str) -> Tuple[str, int]:
    """Apply NFKC and remove invisible/control formatting characters.

    Non-ASCII letters are retained. The returned count covers removed
    zero-width/invisible controls and is used for transformation provenance.
    """
    if not text:
        return "", 0

    stripped_count = 0
    kept: List[str] = []
    for char in text:
        category = unicodedata.category(char)
        is_invisible = bool(ZERO_WIDTH_PATTERN.fullmatch(char))
        # Keep ordinary whitespace needed for prompt structure.
        is_control = category in {"Cc", "Cf"} and char not in {"\t", "\n", "\r"}
        if is_invisible or is_control:
            stripped_count += 1
            continue
        kept.append(char)

    normalized = unicodedata.normalize("NFKC", "".join(kept))
    normalized = normalized.replace("\r\n", "\n").replace("\r", "\n")
    return normalized.strip(), stripped_count


def _looks_like_hex_token(token: str) -> bool:
    candidate = token[2:] if token.lower().startswith("0x") else token
    return len(candidate) >= 16 and len(candidate) % 2 == 0 and bool(
        re.fullmatch(r"[0-9a-fA-F]+", candidate)
    )


def _looks_like_base64_token(token: str) -> bool:
    if len(token) < 16 or not re.fullmatch(r"[A-Za-z0-9+/_-]+={0,2}", token):
        return False
    # Padding, URL-safe markers, or a mixed alphanumeric long token are useful
    # signals; plain words should still be eligible for leetspeak normalization.
    return token.endswith("=") or any(ch in token for ch in "+/_-") or any(
        ch.isdigit() for ch in token
    )


def _looks_like_encoded_token(token: str) -> bool:
    return (
        _looks_like_hex_token(token)
        or _looks_like_base64_token(token)
        or bool(URL_ESCAPE_PATTERN.search(token))
        or bool(HTML_ENTITY_PATTERN.search(token))
    )


def normalize_leetspeak(text: str) -> str:
    """Conservatively normalize common leetspeak without corrupting encodings."""
    if not text:
        return ""

    normalized_tokens: List[str] = []
    for token in text.split():
        # Preserve standalone numeric contexts (#10492, dates, versions).
        if re.fullmatch(r"#?\d+[\d.\-/]*", token) or _looks_like_encoded_token(token):
            normalized_tokens.append(token)
            continue
        if any(char.isalpha() for char in token) or any(
            char in "@!$€" for char in token
        ):
            normalized_tokens.append("".join(LEET_CHAR_MAP.get(ch, ch) for ch in token))
        else:
            normalized_tokens.append(token)
    return " ".join(normalized_tokens)


def normalize_confusables(text: str) -> str:
    """Create a detector-only representation for scoped lookalike mappings."""
    return text.translate(CONFUSABLE_MAP)


def normalize_spacing_for_detection(text: str) -> str:
    """Collapse separators used to split security words, preserving the source."""
    if not text:
        return ""
    compact = text
    # Join runs of individually separated letters (``i.g.n.o.r.e`` and
    # ``i g n o r e``), but do not collapse ordinary multi-letter words.
    compact = re.sub(
        r"(?<![A-Za-z])(?:[A-Za-z][\s._\-,:;|/\\]+){3,}[A-Za-z](?![A-Za-z])",
        lambda match: re.sub(r"[^A-Za-z]", "", match.group(0)),
        compact,
    )
    # Punctuation between ordinary words becomes a detector-only boundary.
    compact = re.sub(r"(?<=[A-Za-z])[._\-,:;|/\\]+(?=[A-Za-z])", " ", compact)
    compact = re.sub(r"\s+", " ", compact).strip()
    if " " not in compact and len(compact) >= 8:
        lower = compact.lower()
        words: List[str] = []
        cursor = 0
        segment_words = (
            "instructions", "instruction", "previous", "developer", "environment",
            "constraints", "password", "override", "jailbreak", "reveal", "system",
            "prompt", "prompts", "directions", "ignore", "disregard", "bypass",
            "hidden", "secret", "execute", "command", "rules", "safety", "all", "and", "the",
        )
        segment_words = tuple(sorted(segment_words, key=len, reverse=True))
        while cursor < len(lower):
            match = next(
                (word for word in segment_words if lower.startswith(word, cursor)),
                None,
            )
            if match is None:
                words = []
                break
            words.append(compact[cursor : cursor + len(match)])
            cursor += len(match)
        if words:
            compact = " ".join(words)
    return compact


def _bounded_text(text: str, limit: int = MAX_DECODED_LENGTH) -> str:
    return text[:limit].strip()


def _printable_text(text: str) -> bool:
    if not text or len(text) < 4 or not any(char.isalpha() for char in text):
        return False
    visible = sum(char.isprintable() or char in "\t\n\r" for char in text)
    return visible / max(1, len(text)) >= 0.85


def _decode_base64_candidates(text: str) -> Iterable[str]:
    count = 0
    for match in BASE64_TOKEN_PATTERN.finditer(text):
        if count >= MAX_CANDIDATES_PER_REPRESENTATION:
            break
        token = match.group(1)
        if len(token) > MAX_DECODED_LENGTH * 2:
            continue
        padded = token + "=" * (-len(token) % 4)
        try:
            decoded_bytes = base64.b64decode(padded, altchars=b"-_", validate=True)
            decoded = decoded_bytes.decode("utf-8")
        except (ValueError, UnicodeDecodeError, base64.binascii.Error):
            continue
        decoded = _bounded_text(decoded)
        if _printable_text(decoded) and decoded.casefold() != token.casefold():
            count += 1
            yield decoded


def _decode_hex_candidates(text: str) -> Iterable[str]:
    count = 0
    for match in ESCAPED_HEX_PATTERN.finditer(text):
        if count >= MAX_CANDIDATES_PER_REPRESENTATION:
            break
        token = match.group(0)
        try:
            decoded = bytes.fromhex(re.sub(r"\\x", "", token, flags=re.IGNORECASE)).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            continue
        decoded = _bounded_text(decoded)
        if _printable_text(decoded):
            count += 1
            yield decoded

    for match in PREFIX_HEX_PATTERN.finditer(text):
        if count >= MAX_CANDIDATES_PER_REPRESENTATION:
            break
        token = match.group(0)
        try:
            decoded = bytes.fromhex(token[2:]).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            continue
        decoded = _bounded_text(decoded)
        if _printable_text(decoded):
            count += 1
            yield decoded

    for match in RAW_HEX_PATTERN.finditer(text):
        if count >= MAX_CANDIDATES_PER_REPRESENTATION:
            break
        token = match.group(0)
        try:
            decoded = bytes.fromhex(token[2:] if token.lower().startswith("0x") else token).decode(
                "utf-8"
            )
        except (ValueError, UnicodeDecodeError):
            continue
        decoded = _bounded_text(decoded)
        if _printable_text(decoded):
            count += 1
            yield decoded


def _decode_rot13_candidate(text: str) -> str | None:
    if not text or not re.search(r"[A-Za-z]{5,}", text):
        return None
    decoded = codecs.decode(text, "rot_13")
    words = set(re.findall(r"[a-z]{4,}", decoded.lower()))
    strong = {
        "ignore", "previous", "instructions", "instruction", "system", "prompt",
        "reveal", "secret", "developer", "override", "jailbreak", "password",
    }
    if ("ignore" in words and ("instruction" in words or "instructions" in words)) or len(
        words.intersection(strong)
    ) >= 2:
        return _bounded_text(decoded)
    return None


def _decode_once(text: str) -> List[Tuple[str, str]]:
    """Return safe one-step payloads with their provenance IDs."""
    decoded: List[Tuple[str, str]] = []
    for payload in _decode_base64_candidates(text):
        decoded.append(("BASE64_DECODED", payload))
    for payload in _decode_hex_candidates(text):
        decoded.append(("HEX_DECODED", payload))
    rot13_payload = _decode_rot13_candidate(text)
    if rot13_payload:
        decoded.append(("ROT13_DECODED", rot13_payload))
    if URL_ESCAPE_PATTERN.search(text):
        unquoted = _bounded_text(urllib.parse.unquote(text))
        if unquoted != text and _printable_text(unquoted):
            decoded.append(("URL_DECODED", unquoted))
    if HTML_ENTITY_PATTERN.search(text):
        unescaped = _bounded_text(html.unescape(text))
        if unescaped != text and _printable_text(unescaped):
            decoded.append(("HTML_ENTITY_DECODED", unescaped))
    return decoded


def _detector_variants(text: str, provenance: Sequence[str]) -> List[Tuple[str, List[str]]]:
    variants: List[Tuple[str, List[str]]] = []
    confusable = normalize_confusables(text)
    if confusable != text:
        variants.append((confusable, [*provenance, "CONFUSABLES_NORMALIZED"]))
    spacing = normalize_spacing_for_detection(confusable)
    if spacing != text and spacing != confusable:
        variants.append((spacing, [*provenance, "SPACING_NORMALIZED"]))
    leet = normalize_leetspeak(confusable)
    if leet != text and leet != confusable:
        variants.append((leet, [*provenance, "LEETSPEAK_NORMALIZED"]))
    leet_spacing = normalize_spacing_for_detection(leet)
    if leet_spacing != text and leet_spacing not in {confusable, spacing, leet}:
        variants.append(
            (leet_spacing, [*provenance, "LEETSPEAK_NORMALIZED", "SPACING_NORMALIZED"])
        )
    return variants


def _build_representations(sanitized: str, stripped_count: int) -> List[Dict[str, Any]]:
    processing_text = sanitized[:MAX_INPUT_LENGTH]
    base_provenance = ["NORMALIZED_UNICODE"]
    if stripped_count:
        base_provenance.append("ZERO_WIDTH_REMOVED")
    normalized = normalize_leetspeak(processing_text)
    normalized_provenance = [*base_provenance]
    if normalized != processing_text:
        normalized_provenance.append("LEETSPEAK_NORMALIZED")

    records: List[Dict[str, Any]] = []
    seen: Dict[str, Dict[str, Any]] = {}
    queue: deque[Dict[str, Any]] = deque()

    def add(text: str, provenance: Sequence[str], depth: int, *, decode: bool = True) -> None:
        if len(records) >= MAX_REPRESENTATIONS and text not in seen:
            return
        value = _bounded_text(text, MAX_INPUT_LENGTH if depth == 0 else MAX_DECODED_LENGTH)
        if not value:
            return
        clean_provenance = list(dict.fromkeys(provenance))
        existing = seen.get(value)
        if existing:
            for item in clean_provenance:
                if item not in existing["provenance"]:
                    existing["provenance"].append(item)
            existing["depth"] = min(existing["depth"], depth)
            return
        record = {
            "id": f"rep-{len(records)}",
            "text": value,
            "provenance": clean_provenance,
            "depth": depth,
        }
        seen[value] = record
        records.append(record)
        if decode:
            queue.append(record)

    add(processing_text, base_provenance, 0)
    if normalized != processing_text:
        add(normalized, normalized_provenance, 0)

    while queue and len(records) < MAX_REPRESENTATIONS:
        record = queue.popleft()
        text = record["text"]
        provenance = record["provenance"]
        depth = record["depth"]

        for variant_text, variant_provenance in _detector_variants(text, provenance):
            add(variant_text, variant_provenance, depth, decode=False)

        if depth >= MAX_DECODE_DEPTH:
            continue
        for transform, payload in _decode_once(text):
            add(payload, [*provenance, transform], depth + 1)

    return records[:MAX_REPRESENTATIONS]


def decode_obfuscation(text: str) -> Dict[str, Any]:
    """Decode safe representations for compatibility with the Phase 1 API."""
    raw = str(text) if text is not None else ""
    sanitized, stripped_count = sanitize_unicode(raw)
    representations = _build_representations(sanitized, stripped_count)
    decoded_payloads: List[str] = []
    labels = {
        "BASE64_DECODED": "Base64",
        "HEX_DECODED": "Hex",
        "ROT13_DECODED": "ROT13",
        "URL_DECODED": "URL",
        "HTML_ENTITY_DECODED": "HTML",
    }
    for representation in representations:
        transforms = [item for item in representation["provenance"] if item in labels]
        if not transforms:
            continue
        entry = f"{labels[transforms[-1]]}: '{representation['text']}'"
        if entry not in decoded_payloads:
            decoded_payloads.append(entry)

    augmented_prompt = sanitized
    if decoded_payloads:
        augmented_prompt = f"{sanitized}\n[Decoded Payload: {' | '.join(decoded_payloads)}]"
    return {
        "has_obfuscation": bool(decoded_payloads),
        "decoded_payloads": decoded_payloads,
        "augmented_prompt": augmented_prompt,
    }


def normalize_input(raw_input: str) -> Dict[str, Any]:
    """Return raw input plus bounded normalized/decoded detector representations."""
    raw_str = str(raw_input) if raw_input is not None else ""
    sanitized_input, stripped_count = sanitize_unicode(raw_str)
    processing_text = sanitized_input[:MAX_INPUT_LENGTH]
    normalized_input = normalize_leetspeak(processing_text)
    representations = _build_representations(sanitized_input, stripped_count)

    decoded_payloads: List[str] = []
    decode_labels = {
        "BASE64_DECODED": "Base64",
        "HEX_DECODED": "Hex",
        "ROT13_DECODED": "ROT13",
        "URL_DECODED": "URL",
        "HTML_ENTITY_DECODED": "HTML",
    }
    for representation in representations:
        for provenance in representation["provenance"]:
            if provenance in decode_labels:
                item = f"{decode_labels[provenance]}: '{representation['text']}'"
                if item not in decoded_payloads:
                    decoded_payloads.append(item)
                break

    has_obfuscation = bool(decoded_payloads) or any(
        item in {"ZERO_WIDTH_REMOVED", "CONFUSABLES_NORMALIZED", "LEETSPEAK_NORMALIZED", "SPACING_NORMALIZED"}
        for rep in representations
        for item in rep["provenance"]
    )
    augmented_prompt = normalized_input
    if decoded_payloads:
        augmented_prompt = f"{normalized_input}\n[Decoded Payload: {' | '.join(decoded_payloads)}]"

    return {
        "raw_input": raw_str,
        "sanitized_input": sanitized_input,
        "normalized_input": normalized_input,
        "normalized_text": normalized_input,
        "augmented_eval_prompt": augmented_prompt,
        "metadata": {
            "stripped_zero_width_count": stripped_count,
            "has_obfuscation": has_obfuscation,
            "decoded_payloads": decoded_payloads,
            "normalized_text": normalized_input,
            "representations": representations,
            "representation_count": len(representations),
            "input_truncated": len(sanitized_input) > MAX_INPUT_LENGTH,
            "limits": {
                "max_input_length": MAX_INPUT_LENGTH,
                "max_decoded_length": MAX_DECODED_LENGTH,
                "max_decode_depth": MAX_DECODE_DEPTH,
                "max_representations": MAX_REPRESENTATIONS,
                "max_candidates_per_representation": MAX_CANDIDATES_PER_REPRESENTATION,
            },
        },
    }
