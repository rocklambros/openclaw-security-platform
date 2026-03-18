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


def _load_evaluator_dir(
    directory: Path, config_root: Path
) -> list[dict[str, Any]]:
    """Load individual evaluator YAML files from a directory.

    Each file should contain a single evaluator config (not wrapped in a list).
    Files are loaded in sorted order for deterministic chain ordering.
    """
    evaluators: list[dict[str, Any]] = []
    if not directory.is_absolute():
        directory = config_root / directory
    if not directory.is_dir():
        logger.warning("Evaluators directory not found: %s", directory)
        return evaluators

    for yaml_file in sorted(directory.glob("*.yaml")) + sorted(directory.glob("*.yml")):
        try:
            with open(yaml_file) as f:
                raw = yaml.safe_load(f)
            if raw and isinstance(raw, dict):
                evaluators.append(raw)
                logger.info("Loaded evaluator file: %s", yaml_file.name)
            elif raw and isinstance(raw, list):
                evaluators.extend(raw)
                logger.info("Loaded %d evaluators from: %s", len(raw), yaml_file.name)
        except Exception:
            logger.exception("Failed to load evaluator file: %s", yaml_file)

    return evaluators


def load_config(path: str | Path | None = None) -> PlatformConfig:
    """Load and validate configuration from YAML.

    Supports three modes:
    1. All evaluators inline in the main config file
    2. Evaluators in a separate directory (evaluators_dir key or default ./evaluators/)
    3. Both — inline evaluators run first, directory evaluators appended (deduplicated by name, last wins)
    """
    config_path = find_config(path)
    config_root = config_path.parent

    with open(config_path) as f:
        raw = yaml.safe_load(f) or {}

    # Resolve evaluators directory
    evaluators_dir = raw.get("evaluators_dir")
    dir_path = Path(evaluators_dir) if evaluators_dir else config_root / "evaluators"

    dir_evaluators = _load_evaluator_dir(dir_path, config_root)

    if dir_evaluators:
        inline = raw.get("evaluators", [])
        # Merge: inline first, then directory. Deduplicate by name — last wins.
        merged: dict[str, dict[str, Any]] = {}
        for ev in inline:
            merged[ev.get("name", "")] = ev
        for ev in dir_evaluators:
            merged[ev.get("name", "")] = ev
        raw["evaluators"] = list(merged.values())

    return PlatformConfig.model_validate(raw)


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
