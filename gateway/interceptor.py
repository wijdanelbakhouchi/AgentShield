import datetime
import uuid
from typing import Any, Dict, Union

from gateway.input_normalizer import (
    decode_obfuscation,
    normalize_input,
    normalize_leetspeak,
)
from state import SecurityPayload


class SecurityGateway:
    """
    Security Gateway (Interceptor Layer):
    Intercepts incoming user requests and inter-agent messages, delegates pre-processing
    and adversarial obfuscation decoding to input_normalizer.py, and attaches execution tracking metadata.
    """

    @staticmethod
    def decode_base64_payloads(text: str) -> str:
        res = decode_obfuscation(text)
        return res["augmented_prompt"]

    @staticmethod
    def normalize_leetspeak(text: str) -> str:
        return normalize_leetspeak(text)

    @classmethod
    def normalize_text(cls, text: str) -> str:
        res = normalize_input(text)
        return res["augmented_eval_prompt"]

    @classmethod
    def process(
        cls,
        payload_input: Union[str, Dict[str, Any]],
        source: str = "user",
        target: str = "agent_orchestrator",
        request_id: str | None = None,
    ) -> SecurityPayload:
        """
        Intercepts input, applies text normalization, enriches execution metadata,
        and constructs a SecurityPayload object.
        """
        if isinstance(payload_input, dict):
            raw_text = payload_input.get(
                "text", payload_input.get("query", str(payload_input))
            )
        else:
            raw_text = str(payload_input) if payload_input is not None else ""

        request_id = request_id or f"req-{uuid.uuid4().hex[:12]}"
        timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
        
        # Delegates to Phase 1 Input Normalization Pipeline
        normalized_data = normalize_input(raw_text)
        normalized_text = normalized_data["augmented_eval_prompt"]

        return SecurityPayload(
            request_id=request_id,
            timestamp=timestamp,
            source=source,
            target=target,
            raw_input=raw_text,
            normalized_input=normalized_text,
            normalization_metadata=normalized_data.get("metadata", {}),
        )
