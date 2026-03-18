"""Tests for multi-file configuration loading."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from openclaw_security.config.loader import load_config


@pytest.fixture()
def config_dir(tmp_path: Path):
    """Create a temporary config directory structure."""
    return tmp_path


def _write_yaml(path: Path, data: dict | list) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.dump(data, default_flow_style=False))


class TestMultiFileConfig:
    """Test evaluator loading from directory."""

    def test_inline_only(self, config_dir: Path):
        """Traditional single-file config still works."""
        _write_yaml(
            config_dir / "config.yaml",
            {
                "evaluators": [
                    {"name": "scanner", "type": "regex", "rules": []}
                ]
            },
        )
        config = load_config(config_dir / "config.yaml")
        assert len(config.evaluators) == 1
        assert config.evaluators[0].name == "scanner"

    def test_directory_only(self, config_dir: Path):
        """Config with no inline evaluators, only directory files."""
        _write_yaml(config_dir / "config.yaml", {"server": {"port": 9920}})
        _write_yaml(
            config_dir / "evaluators" / "secrets.yaml",
            {"name": "secrets", "type": "regex", "rules": []},
        )
        _write_yaml(
            config_dir / "evaluators" / "policies.yaml",
            {"name": "policies", "type": "cel", "rules": []},
        )

        config = load_config(config_dir / "config.yaml")
        assert len(config.evaluators) == 2
        names = {e.name for e in config.evaluators}
        assert names == {"secrets", "policies"}

    def test_inline_plus_directory(self, config_dir: Path):
        """Inline evaluators and directory evaluators are merged."""
        _write_yaml(
            config_dir / "config.yaml",
            {
                "evaluators": [
                    {"name": "inline-scanner", "type": "regex", "rules": []}
                ]
            },
        )
        _write_yaml(
            config_dir / "evaluators" / "ml-detector.yaml",
            {"name": "ml-detector", "type": "ml", "model_path": "./model.onnx", "threshold": 0.8},
        )

        config = load_config(config_dir / "config.yaml")
        assert len(config.evaluators) == 2
        names = [e.name for e in config.evaluators]
        assert names == ["inline-scanner", "ml-detector"]

    def test_directory_overrides_inline_by_name(self, config_dir: Path):
        """If same name appears inline and in directory, directory wins."""
        _write_yaml(
            config_dir / "config.yaml",
            {
                "evaluators": [
                    {"name": "scanner", "type": "regex", "rules": [{"label": "old", "pattern": "old", "action": "warn"}]}
                ]
            },
        )
        _write_yaml(
            config_dir / "evaluators" / "scanner.yaml",
            {"name": "scanner", "type": "regex", "rules": [{"label": "new", "pattern": "new", "action": "block"}]},
        )

        config = load_config(config_dir / "config.yaml")
        assert len(config.evaluators) == 1
        assert config.evaluators[0].rules[0]["label"] == "new"

    def test_sorted_load_order(self, config_dir: Path):
        """Directory files load in alphabetical order."""
        _write_yaml(config_dir / "config.yaml", {})
        _write_yaml(
            config_dir / "evaluators" / "b-second.yaml",
            {"name": "b-second", "type": "regex", "rules": []},
        )
        _write_yaml(
            config_dir / "evaluators" / "a-first.yaml",
            {"name": "a-first", "type": "regex", "rules": []},
        )

        config = load_config(config_dir / "config.yaml")
        names = [e.name for e in config.evaluators]
        assert names == ["a-first", "b-second"]

    def test_custom_evaluators_dir(self, config_dir: Path):
        """evaluators_dir key points to a custom directory."""
        custom_dir = config_dir / "my-rules"
        _write_yaml(
            config_dir / "config.yaml",
            {"evaluators_dir": str(custom_dir)},
        )
        _write_yaml(
            custom_dir / "custom.yaml",
            {"name": "custom", "type": "cel", "rules": []},
        )

        config = load_config(config_dir / "config.yaml")
        assert len(config.evaluators) == 1
        assert config.evaluators[0].name == "custom"

    def test_yml_extension_supported(self, config_dir: Path):
        """Both .yaml and .yml extensions are loaded."""
        _write_yaml(config_dir / "config.yaml", {})
        _write_yaml(
            config_dir / "evaluators" / "from-yaml.yaml",
            {"name": "from-yaml", "type": "regex", "rules": []},
        )
        _write_yaml(
            config_dir / "evaluators" / "from-yml.yml",
            {"name": "from-yml", "type": "regex", "rules": []},
        )

        config = load_config(config_dir / "config.yaml")
        assert len(config.evaluators) == 2

    def test_no_evaluators_dir_no_error(self, config_dir: Path):
        """Missing evaluators directory is fine — just no extra evaluators."""
        _write_yaml(config_dir / "config.yaml", {})
        config = load_config(config_dir / "config.yaml")
        assert len(config.evaluators) == 0

    def test_malformed_file_skipped(self, config_dir: Path):
        """A bad YAML file in the directory is skipped, others still load."""
        _write_yaml(config_dir / "config.yaml", {})
        (config_dir / "evaluators").mkdir()
        (config_dir / "evaluators" / "bad.yaml").write_text(": : : not valid yaml {{{}}")
        _write_yaml(
            config_dir / "evaluators" / "good.yaml",
            {"name": "good", "type": "regex", "rules": []},
        )

        config = load_config(config_dir / "config.yaml")
        assert len(config.evaluators) == 1
        assert config.evaluators[0].name == "good"

    def test_multi_evaluator_file(self, config_dir: Path):
        """A single file can contain a list of evaluators."""
        _write_yaml(config_dir / "config.yaml", {})
        _write_yaml(
            config_dir / "evaluators" / "bundle.yaml",
            [
                {"name": "bundled-a", "type": "regex", "rules": []},
                {"name": "bundled-b", "type": "cel", "rules": []},
            ],
        )

        config = load_config(config_dir / "config.yaml")
        assert len(config.evaluators) == 2
        names = {e.name for e in config.evaluators}
        assert names == {"bundled-a", "bundled-b"}
