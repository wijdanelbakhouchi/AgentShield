import os
import math
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

LLM_PROVIDER = os.getenv("LLM_PROVIDER", "auto").lower()
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "")
OPENAI_MODEL_NAME = os.getenv("OPENAI_MODEL_NAME", "gpt-4o-mini").strip()
GEMINI_MODEL_NAME = os.getenv("GEMINI_MODEL_NAME", "gemini-1.5-flash").strip()
GROQ_MODEL_NAME = os.getenv("GROQ_MODEL_NAME", "openai/gpt-oss-20b").strip()
LLM_TEMPERATURE = float(os.getenv("LLM_TEMPERATURE", "0.7"))

# Phase 12 platform settings. SQLite is the only validated runtime in this
# repository; PostgreSQL is intentionally not claimed until its driver,
# migrations and application startup are covered by integration evidence.
APP_ENV = os.getenv("AGENTSHIELD_ENV", "development").strip().lower()
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./agent_shield.db").strip()

try:
    APPROVAL_TTL_SECONDS = int(os.getenv("APPROVAL_TTL_SECONDS", "600"))
except (TypeError, ValueError):
    APPROVAL_TTL_SECONDS = 600

TOOL_SANDBOX_PATH = os.getenv("AGENTSHIELD_TOOL_SANDBOX", "").strip()


def cors_origins() -> list[str]:
    """Return explicit origins; wildcard CORS is never paired with credentials."""

    raw = os.getenv(
        "AGENTSHIELD_CORS_ORIGINS",
        "http://localhost:5173,http://localhost:3000,http://127.0.0.1:3000",
    )
    origins = [origin.strip().rstrip("/") for origin in raw.split(",") if origin.strip()]
    if "*" in origins:
        raise ValueError("AGENTSHIELD_CORS_ORIGINS must not contain '*' when credentials are enabled")
    return origins


def _float_env(name: str, default: float) -> float:
    """Read a bounded numeric security setting without breaking startup."""
    try:
        return float(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        return default


def _bool_env(name: str, default: bool) -> bool:
    """Read an explicit boolean security setting without truthiness surprises."""
    value = os.getenv(name)
    if value is None:
        return default
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    return default


# The bundled subject/token mapping is intentionally limited to development
# and test environments.  Production can never enable it, even if a stale
# development flag is present; a real deployment must provide its own
# authenticated identity integration.
DEVELOPMENT_AUTH_ENABLED = _bool_env(
    "AGENTSHIELD_DEV_AUTH_ENABLED", APP_ENV in {"development", "test"}
)

# API security is deliberately environment-aware.  A production process must
# have an explicit token mapping and never accepts the bundled development
# identities.  Development can opt into anonymous local demonstrations, but
# the switch is visible in health output and is off in production regardless
# of a stale environment file.
API_AUTH_REQUIRED = _bool_env("AGENTSHIELD_API_AUTH_REQUIRED", APP_ENV == "production")
DEVELOPMENT_ANONYMOUS_DEMO = _bool_env(
    "AGENTSHIELD_DEV_ANONYMOUS_DEMO", APP_ENV in {"development", "test"}
)
HTTPS_DEPLOYMENT = _bool_env("AGENTSHIELD_HTTPS_DEPLOYMENT", False)


# Provider calls are bounded at the client boundary. A failed provider is
# never silently represented as a successful external completion; callers
# receive explicit demo/fallback metadata when this policy is enabled.
LLM_REQUEST_TIMEOUT_SECONDS = _float_env("LLM_REQUEST_TIMEOUT_SECONDS", 20.0)
LLM_FALLBACK_ENABLED = _bool_env("LLM_FALLBACK_ENABLED", True)
# Reliability controls are disabled by default. Evaluation can opt in through
# process-local environment variables so both baseline and protected runs use
# the identical pacing/retry policy without altering security behavior.
LLM_MAX_TRANSIENT_RETRIES = max(0, min(3, int(_float_env("LLM_MAX_TRANSIENT_RETRIES", 0))))
LLM_MIN_REQUEST_INTERVAL_SECONDS = max(0.0, min(30.0, _float_env("LLM_MIN_REQUEST_INTERVAL_SECONDS", 0.0)))


# Canonical security semantics.  These are the selected POST-HARDENING /
# POST-SEMANTIC calibration values; historical Phase 4 values remain under
# experiments/calibration and are not active runtime configuration.
RISK_LOW_MAX = _float_env("RISK_LOW_MAX", 0.07)
RISK_MEDIUM_MAX = _float_env("RISK_MEDIUM_MAX", 0.13)
RISK_HIGH_MAX = _float_env("RISK_HIGH_MAX", 0.16)
POLICY_BLOCK_THRESHOLD = _float_env("POLICY_BLOCK_THRESHOLD", 0.17)

# Canonical additive scorer weights.  Each normalized component is in [0, 1]
# and the simplex is validated below.  The classifier weight is zero because
# no external provider was available during this calibration; the explicit
# heuristic fallback remains observable but does not silently receive weight.
RULE_WEIGHT = _float_env("RULE_WEIGHT", 0.40)
SIMILARITY_WEIGHT = _float_env("SIMILARITY_WEIGHT", 0.30)
CLASSIFIER_WEIGHT = _float_env("CLASSIFIER_WEIGHT", 0.00)
CONTEXT_WEIGHT = _float_env("CONTEXT_WEIGHT", 0.30)

# Calibration selected score-only enforcement.  A detector flag is still
# preserved in telemetry, but it does not bypass the empirically selected
# block threshold.
POLICY_FLAG_OVERRIDE = _bool_env("POLICY_FLAG_OVERRIDE", False)

# Internal detector cut-offs remain explicit and centralized so an active
# path cannot silently acquire a second copy of the same threshold semantics.
THREAT_VECTOR_THRESHOLD = _float_env("THREAT_VECTOR_THRESHOLD", 0.40)
EMBEDDING_MATCH_THRESHOLD = _float_env("EMBEDDING_MATCH_THRESHOLD", 0.35)
THREAT_MEDIUM_THRESHOLD = _float_env("THREAT_MEDIUM_THRESHOLD", RISK_LOW_MAX)
THREAT_HIGH_THRESHOLD = _float_env("THREAT_HIGH_THRESHOLD", RISK_MEDIUM_MAX)
THREAT_CRITICAL_THRESHOLD = _float_env("THREAT_CRITICAL_THRESHOLD", 0.85)
INTER_AGENT_ALLOW_THRESHOLD = _float_env("INTER_AGENT_ALLOW_THRESHOLD", 0.35)

# Phase 19 provenance-aware monitoring.  Provenance tracking is on by default
# because it adds audit value with zero policy impact.  Every risk bonus
# defaults to 0.0, which reproduces the frozen Phase 6.5 calibration operating
# point exactly; experiments enable bonuses explicitly as the provenance-aware
# axis (taint, depth, privileged target).
PROVENANCE_ENABLED = _bool_env("PROVENANCE_ENABLED", True)
PROVENANCE_BONUS_UNTRUSTED = _float_env("PROVENANCE_BONUS_UNTRUSTED", 0.0)
PROVENANCE_BONUS_PER_DEPTH = _float_env("PROVENANCE_BONUS_PER_DEPTH", 0.0)
PROVENANCE_BONUS_PRIVILEGED_TARGET = _float_env(
    "PROVENANCE_BONUS_PRIVILEGED_TARGET", 0.0
)
PROVENANCE_MAX_DEPTH_BONUS = max(1, int(_float_env("PROVENANCE_MAX_DEPTH_BONUS", 3)))

# The calibrated score threshold remains the compatibility default. Hardened
# deployments should select ``banded`` explicitly (as shown in .env.example),
# which makes medium/high bands sanitize or require review. Critical-signal
# overrides apply in both modes and cannot be disabled by this setting.
# ``banded`` maps risk bands to configurable actions:
#   LOW    -> ALLOW
#   MEDIUM -> POLICY_MEDIUM_ACTION    (SANITIZE by default)
#   HIGH   -> POLICY_HIGH_ACTION      (BLOCK by default)
#   CRITICAL -> POLICY_CRITICAL_ACTION (BLOCK by default)
POLICY_MODE = os.getenv("POLICY_MODE", "score_threshold").strip().lower()
POLICY_MEDIUM_ACTION = os.getenv("POLICY_MEDIUM_ACTION", "SANITIZE").strip().upper()
POLICY_HIGH_ACTION = os.getenv("POLICY_HIGH_ACTION", "BLOCK").strip().upper()
POLICY_CRITICAL_ACTION = os.getenv("POLICY_CRITICAL_ACTION", "BLOCK").strip().upper()


def _int_env(name: str, default: int, *, minimum: int = 1) -> int:
    """Read a bounded integer detector safeguard from the environment."""
    try:
        value = int(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        return default
    return max(minimum, value)


MAX_REQUEST_BODY_BYTES = _int_env("AGENTSHIELD_MAX_REQUEST_BODY_BYTES", 262_144)
MAX_PROMPT_LENGTH = _int_env("AGENTSHIELD_MAX_PROMPT_LENGTH", 32_000)
MAX_CONTEXT_LENGTH = _int_env("AGENTSHIELD_MAX_CONTEXT_LENGTH", 96_000)
API_RATE_LIMIT_CHAT_PER_MINUTE = _int_env("AGENTSHIELD_RATE_LIMIT_CHAT_PER_MINUTE", 30)
API_RATE_LIMIT_ANALYZE_PER_MINUTE = _int_env("AGENTSHIELD_RATE_LIMIT_ANALYZE_PER_MINUTE", 60)
API_RATE_LIMIT_ADMIN_PER_MINUTE = _int_env("AGENTSHIELD_RATE_LIMIT_ADMIN_PER_MINUTE", 20)
TOOL_MAX_CALLS_PER_REQUEST = _int_env("AGENTSHIELD_TOOL_MAX_CALLS_PER_REQUEST", 8)
TOOL_MAX_CALLS_PER_AGENT = _int_env("AGENTSHIELD_TOOL_MAX_CALLS_PER_AGENT", 4)
TOOL_MAX_IDENTICAL_CALLS = _int_env("AGENTSHIELD_TOOL_MAX_IDENTICAL_CALLS", 2)
# Live web search is an opt-in egress capability. Keeping it disabled by
# default prevents a prompt from being sent to an unreviewed third party.
LIVE_WEB_SEARCH_ENABLED = _bool_env("AGENTSHIELD_LIVE_WEB_SEARCH_ENABLED", False)
WEB_SEARCH_TIMEOUT_SECONDS = min(30, _int_env("AGENTSHIELD_WEB_SEARCH_TIMEOUT_SECONDS", 4))
OPERATIONAL_LOG_PROMPTS = _bool_env("AGENTSHIELD_OPERATIONAL_LOG_PROMPTS", False)
OPERATIONAL_LOG_MAX_CHARS = _int_env("AGENTSHIELD_OPERATIONAL_LOG_MAX_CHARS", 512)

# A missing semantic model is a visible degraded state, never a zero-risk
# result.  In degraded mode normal conversational work may continue, but the
# tool broker refuses sensitive capabilities and policy escalates suspicious
# content to human review.
SECURITY_DEGRADED_MODE = os.getenv(
    "AGENTSHIELD_SECURITY_DEGRADED_MODE", "restrict_sensitive_tools"
).strip().lower()


# Phase 5 deterministic normalization safeguards.  These limits bound internal
# work without changing the application-level raw input contract or Phase 4
# calibrated scoring/policy values.
MAX_INPUT_LENGTH = _int_env("MAX_INPUT_LENGTH", 100_000)
MAX_DECODED_LENGTH = _int_env("MAX_DECODED_LENGTH", 32_000)
MAX_DECODE_DEPTH = _int_env("MAX_DECODE_DEPTH", 3)
MAX_REPRESENTATIONS = _int_env("MAX_REPRESENTATIONS", 24)
MAX_CANDIDATES_PER_REPRESENTATION = _int_env(
    "MAX_CANDIDATES_PER_REPRESENTATION", 32
)

# Phase 6 local semantic similarity detector.  This detector is evidence-only
# until a post-Phase-6 risk recalibration changes the production scorer policy.
SEMANTIC_SIMILARITY_ENABLED = _bool_env("SEMANTIC_SIMILARITY_ENABLED", True)
SEMANTIC_MODEL_NAME = os.getenv(
    "SEMANTIC_MODEL_NAME", "sentence-transformers/all-MiniLM-L6-v2"
).strip()
SEMANTIC_MODEL_REVISION = os.getenv(
    "SEMANTIC_MODEL_REVISION", "1110a243fdf4706b3f48f1d95db1a4f5529b4d41"
).strip()
SEMANTIC_SIMILARITY_THRESHOLD = _float_env(
    "SEMANTIC_SIMILARITY_THRESHOLD", 0.51
)
SEMANTIC_TOP_K = _int_env("SEMANTIC_TOP_K", 3)
SEMANTIC_BATCH_SIZE = _int_env("SEMANTIC_BATCH_SIZE", 16)
SEMANTIC_MAX_REPRESENTATIONS = _int_env("SEMANTIC_MAX_REPRESENTATIONS", 8)
SEMANTIC_CORPUS_PATH = os.getenv(
    "SEMANTIC_CORPUS_PATH", "experiments/semantic_similarity/attack_corpus.json"
)


def validate_security_configuration() -> None:
    """Fail startup early when calibrated security settings are inconsistent."""
    thresholds = (
        POLICY_BLOCK_THRESHOLD,
        RISK_LOW_MAX,
        RISK_MEDIUM_MAX,
        RISK_HIGH_MAX,
    )
    if any(not 0.0 <= value <= 1.0 for value in thresholds):
        raise ValueError("Security policy and risk thresholds must be between 0 and 1")
    if not RISK_LOW_MAX < RISK_MEDIUM_MAX < RISK_HIGH_MAX:
        raise ValueError("Risk bands must satisfy LOW < MEDIUM < HIGH")
    weights = (RULE_WEIGHT, SIMILARITY_WEIGHT, CLASSIFIER_WEIGHT, CONTEXT_WEIGHT)
    if any(not math.isfinite(value) or value < 0.0 for value in weights):
        raise ValueError("Risk scorer weights must be finite and non-negative")
    if abs(sum(weights) - 1.0) > 1e-6:
        raise ValueError("Risk scorer weights must sum to 1.0")
    if not 0.0 <= SEMANTIC_SIMILARITY_THRESHOLD <= 1.0:
        raise ValueError("Semantic similarity threshold must be between 0 and 1")
    if not DATABASE_URL.startswith("sqlite"):
        raise ValueError("This validated deployment currently supports SQLite DATABASE_URL values only")
    if APP_ENV not in {"development", "test", "production"}:
        raise ValueError("AGENTSHIELD_ENV must be development, test, or production")
    if APP_ENV == "production" and DEVELOPMENT_AUTH_ENABLED:
        raise ValueError("development identities cannot be enabled in production")
    if APP_ENV == "production" and DEVELOPMENT_ANONYMOUS_DEMO:
        raise ValueError("anonymous demonstration mode cannot be enabled in production")
    if APP_ENV == "production" and API_AUTH_REQUIRED and not os.getenv("AGENTSHIELD_API_TOKENS", "").strip():
        raise ValueError("production API authentication requires AGENTSHIELD_API_TOKENS")
    if SECURITY_DEGRADED_MODE not in {"restrict_sensitive_tools", "review_suspicious", "fail_closed"}:
        raise ValueError("AGENTSHIELD_SECURITY_DEGRADED_MODE has an unsupported value")
    if APPROVAL_TTL_SECONDS < 1:
        raise ValueError("APPROVAL_TTL_SECONDS must be at least one second")
    if POLICY_MODE not in {"score_threshold", "banded"}:
        raise ValueError("POLICY_MODE must be score_threshold or banded")
    allowed_actions = {"ALLOW", "SANITIZE", "REVIEW", "BLOCK"}
    for name, value in (
        ("POLICY_MEDIUM_ACTION", POLICY_MEDIUM_ACTION),
        ("POLICY_HIGH_ACTION", POLICY_HIGH_ACTION),
        ("POLICY_CRITICAL_ACTION", POLICY_CRITICAL_ACTION),
    ):
        if value not in allowed_actions:
            raise ValueError(f"{name} must be one of {sorted(allowed_actions)}")
    for name, value in (
        ("PROVENANCE_BONUS_UNTRUSTED", PROVENANCE_BONUS_UNTRUSTED),
        ("PROVENANCE_BONUS_PER_DEPTH", PROVENANCE_BONUS_PER_DEPTH),
        ("PROVENANCE_BONUS_PRIVILEGED_TARGET", PROVENANCE_BONUS_PRIVILEGED_TARGET),
    ):
        if not 0.0 <= value <= 1.0:
            raise ValueError(f"{name} must be between 0 and 1")
    cors_origins()


validate_security_configuration()


def is_llm_available() -> bool:
    """Return whether the selected provider can be initialized.

    This is a configuration signal, not a runtime verification claim. Use
    ``providers.service.validate_provider`` for a real completion.
    """
    from providers.service import get_provider_service

    return bool(get_provider_service().snapshot.configured)


def get_llm():
    """Return the canonical provider service (or a falsey demo service).

    ``ProviderService`` implements the small LangChain-compatible
    ``invoke``/``with_structured_output`` surface used by existing agents, so
    provider-specific branching stays in one module. Fallback remains
    observable through ``providers.service.provider_metadata``.
    """
    from providers.service import get_provider_service

    return get_provider_service()
