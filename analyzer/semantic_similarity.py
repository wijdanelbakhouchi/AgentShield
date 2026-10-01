"""Real local sentence-embedding similarity detection for AgentShield.

The legacy ``threat_evaluator`` matcher is a lexical baseline.  This module is
the only semantic detector on the canonical request path.  It deliberately
does not fall back to lexical scores when the model is unavailable: callers get
an explicit ``unavailable``/``disabled`` status instead.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence

import numpy as np

from config import (
    SEMANTIC_BATCH_SIZE,
    SEMANTIC_CORPUS_PATH,
    SEMANTIC_MAX_REPRESENTATIONS,
    SEMANTIC_MODEL_NAME,
    SEMANTIC_MODEL_REVISION,
    SEMANTIC_SIMILARITY_ENABLED,
    SEMANTIC_SIMILARITY_THRESHOLD,
    SEMANTIC_TOP_K,
)


_DECODE_PROVENANCE = {
    "BASE64_DECODED",
    "HEX_DECODED",
    "ROT13_DECODED",
    "URL_DECODED",
    "HTML_ENTITY_DECODED",
}


def _sha256_json(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _unit_normalize(vectors: Any) -> np.ndarray:
    array = np.asarray(vectors, dtype=np.float32)
    if array.ndim == 1:
        array = array.reshape(1, -1)
    if array.ndim != 2 or array.shape[1] == 0:
        raise ValueError("encoder returned an invalid embedding matrix")
    norms = np.linalg.norm(array, axis=1, keepdims=True)
    norms[norms == 0.0] = 1.0
    return array / norms


class SemanticSimilarityDetector:
    """Lazy, process-local sentence embedding detector.

    ``encoder`` is intentionally injectable for deterministic unit tests.  A
    fixture encoder is never used by the canonical singleton; production
    construction always loads the configured ``SentenceTransformer`` model.
    """

    def __init__(
        self,
        *,
        encoder: Any = None,
        corpus_path: Optional[str] = None,
        model_name: Optional[str] = None,
        model_revision: Optional[str] = None,
        threshold: Optional[float] = None,
        top_k: Optional[int] = None,
        enabled: Optional[bool] = None,
    ) -> None:
        self.corpus_path = Path(corpus_path or SEMANTIC_CORPUS_PATH)
        self.model_name = model_name or SEMANTIC_MODEL_NAME
        self.model_revision = model_revision or SEMANTIC_MODEL_REVISION
        self.threshold = float(SEMANTIC_SIMILARITY_THRESHOLD if threshold is None else threshold)
        self.top_k = max(1, int(SEMANTIC_TOP_K if top_k is None else top_k))
        self.enabled = SEMANTIC_SIMILARITY_ENABLED if enabled is None else bool(enabled)
        self._fixture_encoder = encoder
        self._encoder: Any = encoder
        self._model_runtime = "fixture" if encoder is not None else "sentence-transformers"
        # Even a fixture encoder must pass through the same lazy precompute
        # lifecycle; status becomes ``fixture`` only after successful encoding.
        self._status = "uninitialized"
        self._failure_reason: Optional[str] = None
        self._embedding_dimension: Optional[int] = None
        self._cache_path: Optional[str] = None
        self._load_mode: Optional[str] = None
        self._corpus = self._load_corpus()
        self._corpus_hash = _sha256_json(self._corpus)
        self._corpus_embeddings: Optional[np.ndarray] = None
        self._lock = threading.RLock()

    def _load_corpus(self) -> List[Dict[str, Any]]:
        try:
            document = json.loads(self.corpus_path.read_text(encoding="utf-8"))
            entries = document.get("entries", [])
            if not isinstance(entries, list) or not entries:
                raise ValueError("attack corpus has no entries")
            clean: List[Dict[str, Any]] = []
            seen_ids = set()
            for entry in entries:
                if not isinstance(entry, dict):
                    raise ValueError("attack corpus entries must be objects")
                entry_id = str(entry.get("id", "")).strip()
                text = str(entry.get("text", "")).strip()
                if not entry_id or not text or entry_id in seen_ids:
                    raise ValueError("attack corpus entries require unique id and text")
                seen_ids.add(entry_id)
                clean.append(
                    {
                        "id": entry_id,
                        "category": str(entry.get("category", "UNKNOWN")),
                        "family": str(entry.get("family", "unknown")),
                        "text": text,
                    }
                )
            return clean
        except Exception as exc:
            self._failure_reason = f"corpus_load_failed: {exc}"
            return []

    @property
    def corpus_metadata(self) -> Dict[str, Any]:
        return {
            "path": str(self.corpus_path),
            "entry_count": len(self._corpus),
            "corpus_hash_sha256": self._corpus_hash,
            "corpus_embedding_precomputed": self._corpus_embeddings is not None,
        }

    @property
    def model_metadata(self) -> Dict[str, Any]:
        return {
            "name": self.model_name,
            "revision": self.model_revision,
            "runtime": self._model_runtime,
            "status": self._status,
            "embedding_dimension": self._embedding_dimension,
            "cache_path": self._cache_path,
            "load_mode": self._load_mode,
            "failure_reason": self._failure_reason,
        }

    def status(self) -> Dict[str, Any]:
        """Return runtime status without claiming semantic availability."""
        if self._encoder is None and self.enabled and self._status == "uninitialized":
            self._ensure_ready()
        return {
            "semantic_similarity_enabled": bool(self._encoder is not None and self._status in {"ready", "fixture"}),
            "status": self._status if self.enabled else "disabled",
            "model": self.model_metadata,
            "corpus": self.corpus_metadata,
            "threshold": self.threshold,
        }

    def _load_real_encoder(self) -> Any:
        try:
            from sentence_transformers import SentenceTransformer
        except Exception as exc:  # pragma: no cover - depends on host packages
            raise RuntimeError(f"sentence-transformers import failed: {exc}") from exc

        snapshot = self._cached_snapshot()
        if snapshot is not None:
            self._cache_path = str(snapshot)
            self._load_mode = "local_snapshot"
            return SentenceTransformer(str(snapshot), device="cpu", local_files_only=True)

        # Runtime detection must be reproducible and must not silently send
        # text or runtime metadata to a model hub. A missing exact snapshot is
        # an explicit unavailable/degraded state, not permission to download.
        kwargs: Dict[str, Any] = {"device": "cpu", "local_files_only": True}
        if self.model_revision:
            kwargs["revision"] = self.model_revision
        self._load_mode = "local_cache_required"
        return SentenceTransformer(self.model_name, **kwargs)

    def _cached_snapshot(self) -> Optional[Path]:
        """Resolve the exact pinned Hugging Face snapshot when cached locally."""
        if not self.model_revision:
            return None

        model_key = f"models--{self.model_name.replace('/', '--')}"
        roots: List[Path] = []
        for name in ("HUGGINGFACE_HUB_CACHE", "TRANSFORMERS_CACHE"):
            value = os.getenv(name)
            if value:
                roots.append(Path(value).expanduser())
        hf_home = os.getenv("HF_HOME")
        if hf_home:
            roots.append(Path(hf_home).expanduser() / "hub")
        roots.append(Path.home() / ".cache" / "huggingface" / "hub")

        seen = set()
        for root in roots:
            key = str(root.resolve())
            if key in seen:
                continue
            seen.add(key)
            candidate = root / model_key / "snapshots" / self.model_revision
            if (
                candidate.is_dir()
                and (candidate / "modules.json").is_file()
                and (candidate / "config.json").is_file()
            ):
                return candidate
        return None

    def _encode(self, texts: Sequence[str]) -> np.ndarray:
        if self._encoder is None:
            raise RuntimeError("semantic encoder is not loaded")
        if not texts:
            return np.empty((0, self._embedding_dimension or 0), dtype=np.float32)
        if hasattr(self._encoder, "encode"):
            vectors = self._encoder.encode(
                list(texts),
                batch_size=SEMANTIC_BATCH_SIZE,
                normalize_embeddings=True,
                convert_to_numpy=True,
                show_progress_bar=False,
            )
        else:
            vectors = self._encoder(list(texts))
        result = _unit_normalize(vectors)
        if self._embedding_dimension is None:
            self._embedding_dimension = int(result.shape[1])
        elif result.shape[1] != self._embedding_dimension:
            raise ValueError("encoder returned inconsistent embedding dimensions")
        return result

    def _ensure_ready(self) -> bool:
        with self._lock:
            if not self.enabled:
                self._status = "disabled"
                return False
            if self._status in {"ready", "fixture", "unavailable"}:
                return self._status in {"ready", "fixture"}
            if self._failure_reason and not self._corpus:
                self._status = "unavailable"
                return False
            try:
                if self._encoder is None:
                    self._encoder = self._load_real_encoder()
                corpus_vectors = self._encode([entry["text"] for entry in self._corpus])
                self._corpus_embeddings = corpus_vectors
                self._status = "fixture" if self._fixture_encoder is not None else "ready"
                return True
            except Exception as exc:  # explicit no-fallback behavior
                self._failure_reason = f"model_runtime_failed: {exc}"
                self._status = "unavailable"
                self._encoder = None
                self._corpus_embeddings = None
                return False

    @staticmethod
    def candidate_representations(
        normalized_input: str, representations: Optional[Iterable[Dict[str, Any]]] = None
    ) -> List[Dict[str, Any]]:
        """Select bounded meaningful normalized/decoded representations.

        Opaque encoded strings are not embedded as independent candidates;
        decoded and normalized forms retain their provenance for explanations.
        """
        candidates: List[Dict[str, Any]] = []
        seen_text = set()

        def add(rep_id: str, text: Any, provenance: Any, depth: Any = 0) -> None:
            value = str(text or "").strip()
            if not value or value in seen_text:
                return
            seen_text.add(value)
            provenance_list = [str(item) for item in (provenance or [])]
            candidates.append(
                {
                    "representation_id": rep_id,
                    "text": value,
                    "provenance": provenance_list,
                    "depth": int(depth or 0),
                }
            )

        add("normalized-input", normalized_input, ["NORMALIZED_INPUT"], 0)
        for index, rep in enumerate(representations or []):
            if not isinstance(rep, dict):
                continue
            provenance = rep.get("provenance", [])
            # Keep normalized variants and decoded payloads, but skip an
            # untouched opaque encoding that cannot carry semantic meaning yet.
            if not provenance or not (
                set(str(item) for item in provenance) & _DECODE_PROVENANCE
            ) and not any(
                str(item).endswith("NORMALIZED") or str(item) == "ZERO_WIDTH_REMOVED"
                for item in provenance
            ):
                continue
            add(str(rep.get("id", f"representation-{index}")), rep.get("text"), provenance, rep.get("depth", 0))
            if len(candidates) >= SEMANTIC_MAX_REPRESENTATIONS:
                break
        return candidates[:SEMANTIC_MAX_REPRESENTATIONS]

    def detect(
        self,
        normalized_input: str,
        representations: Optional[Iterable[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Score candidate representations against precomputed corpus vectors."""
        result: Dict[str, Any] = {
            "detector": "SEMANTIC_SIMILARITY",
            "semantic_similarity_enabled": False,
            "status": "disabled" if not self.enabled else "uninitialized",
            "threshold": self.threshold,
            "top_match": None,
            "matches": [],
            "findings": [],
            "representations_evaluated": 0,
            "corpus": self.corpus_metadata,
            "model": self.model_metadata,
        }
        if not self._ensure_ready():
            result.update(self.status())
            result["corpus"] = self.corpus_metadata
            result["model"] = self.model_metadata
            return result

        candidates = self.candidate_representations(normalized_input, representations)
        result["representations_evaluated"] = len(candidates)
        if not candidates or self._corpus_embeddings is None:
            result.update(self.status())
            return result

        try:
            input_vectors = self._encode([item["text"] for item in candidates])
        except Exception as exc:
            # Runtime failures after corpus initialization are still explicit;
            # do not emit a partial or lexical substitute score.
            with self._lock:
                self._failure_reason = f"model_runtime_failed: {exc}"
                self._status = "unavailable"
                self._encoder = None
                self._corpus_embeddings = None
            result.update(self.status())
            result["corpus"] = self.corpus_metadata
            result["model"] = self.model_metadata
            return result
        scores = input_vectors @ self._corpus_embeddings.T
        best_by_entry: Dict[int, Dict[str, Any]] = {}
        for input_index, candidate in enumerate(candidates):
            for corpus_index, score in enumerate(scores[input_index]):
                numeric_score = float(np.clip(score, -1.0, 1.0))
                current = best_by_entry.get(corpus_index)
                if current is None or numeric_score > current["similarity"]:
                    entry = self._corpus[corpus_index]
                    best_by_entry[corpus_index] = {
                        "corpus_id": entry["id"],
                        "category": entry["category"],
                        "family": entry["family"],
                        "similarity": round(numeric_score, 6),
                        "representation_id": candidate["representation_id"],
                        "provenance": candidate["provenance"],
                        "representation_depth": candidate["depth"],
                    }
        matches = sorted(best_by_entry.values(), key=lambda item: item["similarity"], reverse=True)[: self.top_k]
        findings = [item for item in matches if item["similarity"] >= self.threshold]
        result.update(
            {
                "semantic_similarity_enabled": True,
                "status": "ready" if self._fixture_encoder is None else "fixture",
                "top_match": matches[0] if matches else None,
                "matches": matches,
                "findings": findings,
                "flagged": bool(findings),
                "corpus": self.corpus_metadata,
                "model": self.model_metadata,
            }
        )
        return result


_DETECTOR: Optional[SemanticSimilarityDetector] = None
_DETECTOR_LOCK = threading.Lock()


def get_semantic_detector() -> SemanticSimilarityDetector:
    """Return the canonical lazy singleton used by ``RiskAnalyzer``."""
    global _DETECTOR
    if _DETECTOR is None:
        with _DETECTOR_LOCK:
            if _DETECTOR is None:
                _DETECTOR = SemanticSimilarityDetector()
    return _DETECTOR


def reset_semantic_detector_for_tests() -> None:
    """Reset the singleton for isolated tests; never called by production code."""
    global _DETECTOR
    with _DETECTOR_LOCK:
        _DETECTOR = None
