"""Relevance scoring and structured evidence handling.

This module provides:
1. Semantic & token-level relevance scoring between queries and retrieved snippets.
2. Structured EvidenceItem parsing, sanitization, and filtering against relevance thresholds.
3. Curated local reference material for a few foundational technical subjects.
4. Deterministic safe fallback generation when evidence is insufficient or unverified.
"""

from __future__ import annotations

import datetime
import re
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
from pydantic import BaseModel, Field

from state import TrustLevel


class EvidenceItem(BaseModel):
    """Structured representation of a single external evidence snippet."""

    content: str = Field(description="Cleaned, sanitized evidence text")
    source: str = Field(default="unknown", description="Source title or origin")
    url: Optional[str] = Field(default=None, description="Source URL or path")
    source_type: str = Field(default="web", description="web, database, document, or tool")
    relevance_score: float = Field(default=0.0, description="Relevance score (0.0 to 1.0) against query")
    trusted: bool = Field(default=False, description="Whether this content is from a trusted internal source")
    trust_level: TrustLevel = Field(default=TrustLevel.EXTERNAL_UNTRUSTED, description="Provenance trust level")
    security_flags: List[str] = Field(default_factory=list, description="Security flags detected in this snippet")
    timestamp: str = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())


# ---------------------------------------------------------------------------
# Curated Local Reference Material
# ---------------------------------------------------------------------------

VERIFIED_DOMAIN_KNOWLEDGE: Dict[str, Dict[str, Any]] = {
    "api": {
        "title": "Application Programming Interface (API)",
        "summary": "An API (Application Programming Interface) is a set of defined rules, specifications, and protocols that enables different software applications to communicate and exchange data with each other.",
        "detailed_content": (
            "### Application Programming Interface (API)\n\n"
            "An **API (Application Programming Interface)** is a computing interface that defines interactions between multiple software intermediaries. It defines the kinds of calls or requests that can be made, how to make them, the data formats that should be used, and the conventions to follow.\n\n"
            "**Key Characteristics:**\n"
            "- **Standard Protocols:** Commonly implemented using REST (HTTP/JSON), GraphQL, gRPC, or SOAP.\n"
            "- **Abstraction Layer:** Hides internal system complexity while exposing clean, secure operational endpoints.\n"
            "- **Interoperability:** Enables seamless integration across distributed architectures, cloud services, and microservices.\n"
            "- **Authentication & Governance:** Secured via API keys, OAuth 2.0 tokens, rate limiting, and runtime security gateways."
        ),
        "keywords": ["api", "application programming interface", "rest", "graphql", "grpc", "endpoint", "http"],
    },
    "cybersecurity": {
        "title": "Cybersecurity Fundamentals",
        "summary": "Cybersecurity is the practice of protecting systems, networks, devices, and data from digital attacks, unauthorized access, and exploitation.",
        "detailed_content": (
            "### Cybersecurity Principles & Defense-in-Depth\n\n"
            "**Cybersecurity** encompasses the technologies, processes, and controls designed to safeguard computer systems, networks, programs, and data from cyberattacks.\n\n"
            "**Core Pillars (The CIA Triad):**\n"
            "- **Confidentiality:** Ensuring information is accessible only to authorized entities.\n"
            "- **Integrity:** Maintaining the accuracy, consistency, and trustworthiness of data across its lifecycle.\n"
            "- **Availability:** Ensuring reliable access to systems and information when needed.\n\n"
            "**Key Defense Mechanisms:**\n"
            "- Multi-factor authentication (MFA) and Role-Based Access Control (RBAC).\n"
            "- Runtime intrusion detection and behavioral monitoring.\n"
            "- Encryption in transit (TLS 1.3) and at rest (AES-256).\n"
            "- Continuous vulnerability management and zero-trust architecture."
        ),
        "keywords": ["cybersecurity", "security", "cia triad", "firewall", "encryption", "vulnerability", "infosec"],
    },
    "machine_learning": {
        "title": "Machine Learning (ML)",
        "summary": "Machine Learning is a subfield of artificial intelligence focused on building algorithms that learn patterns from data to make predictions or decisions without being explicitly programmed.",
        "detailed_content": (
            "### Machine Learning (ML) Overview\n\n"
            "**Machine Learning (ML)** is a discipline of Artificial Intelligence where computational models improve their performance on specific tasks through exposure to empirical data.\n\n"
            "**Primary Paradigms:**\n"
            "- **Supervised Learning:** Training models on labeled datasets (e.g., classification, regression).\n"
            "- **Unsupervised Learning:** Discovering latent structures in unlabeled data (e.g., clustering, dimensionality reduction).\n"
            "- **Reinforcement Learning:** Agents learning optimal decision policies through reward signals and environment interactions.\n"
            "- **Deep Learning:** Utilizing multi-layered neural networks for complex representations in vision, language, and tabular domains."
        ),
        "keywords": ["machine learning", "ml", "artificial intelligence", "ai", "neural network", "deep learning", "supervised"],
    },
    "docker": {
        "title": "Docker & Containerization",
        "summary": "Docker is an open-source platform that automates the deployment, scaling, and management of applications inside lightweight, isolated containers.",
        "detailed_content": (
            "### Docker Containerization Platform\n\n"
            "**Docker** enables developers to package applications with all of their dependencies, configuration files, and system libraries into standardized units called **containers**.\n\n"
            "**Key Concepts:**\n"
            "- **Docker Image:** An immutable, layered blueprint containing application code and runtime environment.\n"
            "- **Docker Container:** A runnable, isolated instance of an image sharing the host OS kernel via Linux namespaces and cgroups.\n"
            "- **Dockerfile:** A declarative text script defining the steps to build a container image.\n"
            "- **Docker Compose:** A tool for defining and executing multi-container Docker applications via YAML specification."
        ),
        "keywords": ["docker", "container", "containerization", "dockerfile", "docker compose", "image"],
    },
    "langchain": {
        "title": "LangChain Framework",
        "summary": "LangChain is an open-source orchestration framework designed to simplify the construction of applications powered by Large Language Models (LLMs).",
        "detailed_content": (
            "### LangChain Architecture\n\n"
            "**LangChain** provides modular abstractions and tooling for integrating Large Language Models into complex software workflows.\n\n"
            "**Core Components:**\n"
            "- **Chains & Graphs:** Structured sequencing of LLM calls, tool executions, and state transformations (LangGraph).\n"
            "- **Model I/O:** Standardized interfaces for chat models, embedding providers, and output parsers.\n"
            "- **Retrieval-Augmented Generation (RAG):** Document loaders, text splitters, and vector store connectors for contextual grounding.\n"
            "- **Agentic Workflows:** Autonomous decision loops leveraging tools and policy constraints."
        ),
        "keywords": ["langchain", "langgraph", "llm framework", "rag", "agents", "vectorstore"],
    },
}


def lookup_domain_knowledge(query: str) -> Optional[Dict[str, Any]]:
    """Lookup curated local reference text for foundational technical topics."""
    normalized = query.lower().strip()
    clean_words = set(re.findall(r"\b[a-z0-9_]+\b", normalized))

    # Check direct keys
    for key, data in VERIFIED_DOMAIN_KNOWLEDGE.items():
        if key in clean_words or key.replace("_", " ") in normalized:
            return data
        for kw in data.get("keywords", []):
            if " " in kw:
                if kw in normalized or set(kw.split()).issubset(clean_words):
                    return data
            else:
                if kw in clean_words or re.search(r"\b" + re.escape(kw) + r"\b", normalized):
                    return data
    return None



# ---------------------------------------------------------------------------
# Relevance Scoring
# ---------------------------------------------------------------------------

def _tokenize(text: str) -> List[str]:
    """Tokenize text into lowercase alphanumeric words excluding trivial stop words."""
    stop_words = {
        "a", "an", "the", "is", "are", "was", "were", "in", "on", "at", "by",
        "for", "with", "about", "against", "between", "into", "through", "during",
        "before", "after", "above", "below", "to", "from", "up", "down", "of",
        "off", "over", "under", "again", "further", "then", "once", "here",
        "there", "when", "where", "why", "how", "all", "any", "both", "each",
        "few", "more", "most", "other", "some", "such", "no", "nor", "not",
        "only", "own", "same", "so", "than", "too", "very", "can", "will",
        "just", "don", "should", "now", "what", "which", "who", "whom", "this",
        "that", "these", "those", "am", "it", "its", "tell", "me", "explain",
        "define", "give", "show", "describe", "please",
    }
    words = re.findall(r"\b[a-zA-Z0-9_\-]+\b", text.lower())
    return [w for w in words if w not in stop_words and len(w) > 1]


def calculate_relevance(query: str, snippet: str) -> float:
    """
    Calculate the semantic and lexical relevance score between a query and a candidate snippet.
    
    Returns a float between 0.0 (completely irrelevant) and 1.0 (highly relevant).
    Uses SentenceTransformers embeddings when ready, supplemented with BM25/Jaccard token overlap.
    """
    if not query or not snippet:
        return 0.0

    q_clean = query.strip()
    s_clean = snippet.strip()

    if not q_clean or not s_clean:
        return 0.0

    q_tokens = _tokenize(q_clean)
    s_tokens = _tokenize(s_clean)

    if not q_tokens:
        q_tokens = [w for w in re.findall(r"\b\w+\b", q_clean.lower()) if len(w) > 1]
    if not s_tokens:
        s_tokens = [w for w in re.findall(r"\b\w+\b", s_clean.lower()) if len(w) > 1]

    if not q_tokens or not s_tokens:
        return 0.0

    # 1. Lexical Token Overlap (Jaccard + Query Coverage)
    q_set = set(q_tokens)
    s_set = set(s_tokens)
    overlap = q_set.intersection(s_set)
    
    query_coverage = len(overlap) / len(q_set) if q_set else 0.0
    jaccard = len(overlap) / len(q_set.union(s_set)) if (q_set or s_set) else 0.0

    # Key acronym / exact phrase bonus
    exact_bonus = 0.0
    for q_tok in q_tokens:
        if len(q_tok) >= 3 and q_tok in s_clean.lower():
            exact_bonus += 0.1
    exact_bonus = min(exact_bonus, 0.3)

    lexical_score = min(1.0, (query_coverage * 0.6) + (jaccard * 0.2) + exact_bonus)

    # 2. Embedding-based Semantic Similarity (if SentenceTransformers is initialized)
    semantic_score = None
    try:
        from analyzer.semantic_similarity import get_semantic_detector
        detector = get_semantic_detector()
        if detector._ensure_ready() and detector._encoder is not None:
            vectors = detector._encode([q_clean, s_clean[:512]])
            if vectors.shape[0] == 2:
                cosine = float(np.dot(vectors[0], vectors[1]))
                semantic_score = max(0.0, min(1.0, cosine))
    except Exception:
        semantic_score = None

    if semantic_score is not None:
        # Composite score: 60% semantic embedding + 40% lexical overlap
        final_score = (semantic_score * 0.6) + (lexical_score * 0.4)
    else:
        final_score = lexical_score

    # Penalize low query term coverage to prevent semantic hallucination / drift
    if q_set and query_coverage < 0.5:
        coverage_factor = max(0.05, (query_coverage / 0.5) ** 1.5)
        final_score = final_score * coverage_factor

    return round(max(0.0, min(1.0, final_score)), 4)


# ---------------------------------------------------------------------------
# Evidence Parsing, Sanitization & Filtering
# ---------------------------------------------------------------------------

def sanitize_evidence_text(raw_text: str) -> str:
    """Neutralize instruction overrides and dangerous markup in external snippets."""
    if not raw_text:
        return ""
    
    cleaned = raw_text
    
    # Strip prompt injection patterns and tag boundaries
    cleaned = re.sub(r"TRUSTED APPLICATION INSTRUCTION:[^\n]*\n?", "", cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r"<\/?(?:untrusted_content|untrusted_data|external_data|user_input|agent_data|system_prompt|system)[^>]*>", "", cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r"\[(?:untrusted_content|untrusted_data|external_data|user_input|agent_data|boundary)_TAG_NEUTRALIZED\]", "", cleaned, flags=re.IGNORECASE)
    
    # Neutralize command / override keywords inside external data
    override_patterns = [
        r"(?i)\bignore\s+(?:all\s+)?previous\s+instructions\b",
        r"(?i)\byou\s+are\s+now\b",
        r"(?i)\bact\s+as\s+an?\s+(?:unrestricted|admin|dan|developer)\b",
        r"(?i)\breveal\s+(?:your\s+)?(?:system\s+prompt|api_key|secrets?)\b",
        r"(?i)\bforget\s+your\s+instructions\b",
    ]
    for pattern in override_patterns:
        cleaned = re.sub(pattern, "[UNTRUSTED_INSTRUCTION_REMOVED]", cleaned)

    return cleaned.strip()


def parse_raw_search_results(raw_output: str) -> List[Dict[str, str]]:
    """Parse raw web search text into distinct source items."""
    if not raw_output or not raw_output.strip():
        return []

    # Check for Source [X]: format
    source_blocks = re.split(r"(?=Source \[\d+\]:)", raw_output)
    parsed: List[Dict[str, str]] = []

    for block in source_blocks:
        block = block.strip()
        if not block:
            continue
        title_match = re.search(r"Source \[\d+\]:\s*([^\n]+)", block)
        summary_match = re.search(r"Summary:\s*([\s\S]*?)(?=URL:|$)", block)
        url_match = re.search(r"URL:\s*([^\n]+)", block)

        title = title_match.group(1).strip() if title_match else "Web Source"
        summary = summary_match.group(1).strip() if summary_match else block
        url = url_match.group(1).strip() if url_match else None

        if summary:
            parsed.append({"title": title, "summary": summary, "url": url})

    if not parsed and raw_output.strip():
        # Generic single block
        parsed.append({"title": "External Reference", "summary": raw_output.strip(), "url": None})

    return parsed


def filter_and_structure_evidence(
    query: str,
    raw_tool_outputs: str,
    threshold: float = 0.22,
) -> Tuple[List[EvidenceItem], List[Dict[str, Any]]]:
    """
    Parse raw tool results, sanitize content, calculate relevance to query,
    filter out irrelevant noise, and return (valid_evidence, rejected_items).
    """
    valid_evidence: List[EvidenceItem] = []
    rejected_items: List[Dict[str, Any]] = []

    if not query or not raw_tool_outputs:
        return valid_evidence, rejected_items

    parsed_sources = parse_raw_search_results(raw_tool_outputs)

    for item in parsed_sources:
        title = item.get("title", "")
        summary = item.get("summary", "")
        url = item.get("url")

        sanitized_summary = sanitize_evidence_text(summary)
        if not sanitized_summary or len(sanitized_summary) < 10:
            continue

        # Check for security flags inside external snippet
        flags: List[str] = []
        if "[UNTRUSTED_INSTRUCTION_REMOVED]" in sanitized_summary:
            flags.append("POTENTIAL_INDIRECT_PROMPT_INJECTION")

        # Calculate relevance
        relevance = calculate_relevance(query, f"{title} {sanitized_summary}")

        if relevance >= threshold:
            valid_evidence.append(
                EvidenceItem(
                    content=sanitized_summary,
                    source=title,
                    url=url,
                    source_type="web",
                    relevance_score=relevance,
                    trusted=False,
                    trust_level=TrustLevel.EXTERNAL_UNTRUSTED,
                    security_flags=flags,
                )
            )
        else:
            rejected_items.append({
                "title": title,
                "summary": sanitized_summary[:150] + "...",
                "relevance_score": relevance,
                "reason": f"Low relevance ({relevance:.3f} < threshold {threshold:.3f})",
            })

    # Sort valid evidence by relevance score descending
    valid_evidence.sort(key=lambda ev: ev.relevance_score, reverse=True)
    return valid_evidence, rejected_items


def safe_fallback_response(query: str, reason: str = "insufficient_evidence") -> str:
    """Return a deterministic, safe, polite response when evidence is missing or untrusted."""
    clean_q = query.strip()
    return (
        f"I do not have enough reliable or verified information to answer '{clean_q}' accurately.\n\n"
        "AgentShield did not find sufficient evidence for a reliable factual response. This is a limited evidence-presence safeguard, not a hallucination-prevention guarantee."
    )
