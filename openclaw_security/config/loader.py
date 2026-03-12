"""Configuration loader — reads YAML config and builds the evaluator chain."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml

from openclaw_security.config.schema import PlatformConfig
from openclaw_security.engine.chain import EvaluatorChain
from openclaw_security.evaluators import EVALUATOR_REGISTRY
from openclaw_security.evaluators.base import Evaluator

logger = logging.getLogger(__name__)

DEFAULT_CONFIG_PATHS = [
    Path("openclaw-security.yaml"),
    Path("openclaw-security.yml"),
    Path("config.yaml"),
]


def find_config(path: str | Path | None = None) -> Path:
    """Locate the config file."""
    if path:
        p = Path(path)
        if p.exists():
            return p
        raise FileNotFoundError(f"Config not found: {p}")

    for default in DEFAULT_CONFIG_PATHS:
        if default.exists():
            return default

    raise FileNotFoundError(
        f"No config file found. Tried: {[str(p) for p in DEFAULT_CONFIG_PATHS]}"
    )


def load_config(path: str | Path | None = None) -> PlatformConfig:
    """Load and validate configuration from YAML."""
    config_path = find_config(path)
    with open(config_path) as f:
        raw = yaml.safe_load(f)
    return PlatformConfig.model_validate(raw or {})


def build_chain(config: PlatformConfig) -> EvaluatorChain:
    """Build an evaluator chain from the loaded config."""
    chain = EvaluatorChain()

    for ec in config.evaluators:
        if not ec.enabled:
            logger.info("Evaluator %s is disabled — skipping", ec.name)
            continue

        evaluator_cls = EVALUATOR_REGISTRY.get(ec.type)
        if evaluator_cls is None:
            logger.error("Unknown evaluator type: %s (evaluator: %s)", ec.type, ec.name)
            continue

        try:
            evaluator = evaluator_cls(name=ec.name, config=ec.to_evaluator_dict())
            chain.add(evaluator)
            logger.info("Loaded evaluator: %s (type=%s, stages=%s)", ec.name, ec.type, ec.stages)
        except Exception:
            logger.exception("Failed to initialize evaluator: %s", ec.name)

    logger.info("Evaluator chain ready: %s", chain)
    return chain
