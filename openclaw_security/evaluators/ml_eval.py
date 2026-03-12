"""ML evaluator — local ONNX model inference for learned detection.

Runs classification models (prompt injection, anomaly detection, toxicity)
via ONNX Runtime for fast, local inference with no external API calls.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import numpy as np

from openclaw_security.engine.context import EvalContext
from openclaw_security.engine.result import Action, EvalResult
from openclaw_security.evaluators.base import Evaluator

logger = logging.getLogger(__name__)


class MLEvaluator(Evaluator):
    eval_type = "ml"
    """Run ONNX models against event text for classification.

    Config shape::

        name: prompt-injection-detector
        type: ml
        stages: [message.before]
        model_path: ./models/prompt-injection-v3.onnx
        threshold: 0.85
        action: block
        label: prompt_injection
        max_length: 512
        tokenizer: whitespace   # "whitespace" (bag-of-words) or "char" (char-level)
    """

    def __init__(self, name: str, config: dict[str, Any]) -> None:
        super().__init__(name, config)
        self._model_path = Path(config["model_path"])
        self._threshold: float = config.get("threshold", 0.85)
        self._action = Action(config.get("action", "block"))
        self._label: str = config.get("label", "malicious")
        self._max_length: int = config.get("max_length", 512)
        self._tokenizer_type: str = config.get("tokenizer", "whitespace")
        self._session = None

    def _get_session(self) -> Any:
        if self._session is None:
            try:
                import onnxruntime as ort

                self._session = ort.InferenceSession(
                    str(self._model_path),
                    providers=["CPUExecutionProvider"],
                )
            except Exception:
                logger.exception("Failed to load ONNX model: %s", self._model_path)
                raise
        return self._session

    def _tokenize(self, text: str) -> np.ndarray:
        """Simple tokenization — maps text to numeric input array.

        For production, users should supply a proper tokenizer config or
        a custom evaluator subclass that uses HuggingFace tokenizers.
        """
        if self._tokenizer_type == "char":
            # Character-level: map each char to its ordinal, truncate to max_length chars
            text = text[:self._max_length]
            ids = [ord(c) % 256 for c in text]
        else:
            # Whitespace: deterministic token → int mapping, truncate to max_length tokens
            tokens = text.lower().split()[:self._max_length]
            ids = [sum(ord(c) * (i + 1) for i, c in enumerate(t)) % 49_999 + 1 for t in tokens]

        # Pad / truncate to max_length
        if len(ids) < self._max_length:
            ids += [0] * (self._max_length - len(ids))
        else:
            ids = ids[: self._max_length]

        return np.array([ids], dtype=np.int64)

    async def evaluate(self, ctx: EvalContext) -> EvalResult:
        text = ctx.searchable_text()
        if not text.strip():
            return self._result()

        try:
            session = self._get_session()
        except Exception:
            return self._result(
                action=Action.WARN,
                confidence=0.0,
                reason=f"ML model unavailable: {self._model_path}",
            )

        try:
            input_ids = self._tokenize(text)
            input_name = session.get_inputs()[0].name
            outputs = session.run(None, {input_name: input_ids})

            # Expect output shape [1, num_classes] with softmax / sigmoid scores
            scores = outputs[0][0]
            if len(scores) == 1:
                # Binary sigmoid output
                confidence = float(scores[0])
            else:
                # Multi-class — take the positive class score (index 1)
                confidence = float(scores[1]) if len(scores) > 1 else float(scores[0])

            if confidence >= self._threshold:
                return self._result(
                    action=self._action,
                    confidence=confidence,
                    reason=f"ML model detected {self._label} (confidence: {confidence:.2f})",
                    metadata={"label": self._label, "scores": scores.tolist()},
                )

            return self._result(confidence=1.0 - confidence)

        except Exception:
            logger.exception("ML inference failed")
            return self._result(
                action=Action.WARN,
                confidence=0.0,
                reason="ML inference error",
            )
