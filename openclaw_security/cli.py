"""CLI entry point — subcommands for serve, proxy, and setup."""

from __future__ import annotations

import argparse
import json
import logging
import subprocess
import sys
from pathlib import Path

logger = logging.getLogger("openclaw_security")


def _run_server(args: argparse.Namespace) -> None:
    """Start the evaluation server or proxy."""
    from openclaw_security.server import app, load_config, _mode  # noqa: F811
    import openclaw_security.server as srv
    import uvicorn

    srv._mode = args.mode

    logging.basicConfig(
        level=getattr(logging, args.log_level.upper()),
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )

    app.state.config_path = args.config
    config = load_config(args.config)

    host = args.host or config.server.host
    port = args.port or config.server.port
    socket_path = args.socket or config.server.unix_socket

    if socket_path:
        logger.info("Listening on unix socket: %s", socket_path)
        uvicorn.run(app, uds=socket_path, log_level=args.log_level)
    else:
        logger.info("Listening on http://%s:%d", host, port)
        uvicorn.run(app, host=host, port=port, log_level=args.log_level)


def _copy_auth_profile(provider_name: str) -> None:
    """Copy the existing Anthropic API key to the new provider in all agent auth profiles."""
    agents_dir = Path.home() / ".openclaw" / "agents"
    if not agents_dir.is_dir():
        print("  WARNING: No agents directory found — you may need to configure auth manually.")
        return

    copied = False
    for agent_dir in agents_dir.iterdir():
        auth_file = agent_dir / "agent" / "auth-profiles.json"
        if not auth_file.exists():
            continue

        try:
            data = json.loads(auth_file.read_text())
            profiles = data.get("profiles", {})

            # Find existing Anthropic key
            anthropic_key = None
            for profile_id, profile in profiles.items():
                if profile.get("provider") == "anthropic" and profile.get("key"):
                    anthropic_key = profile["key"]
                    break

            if not anthropic_key:
                continue

            # Add profile for the secured provider
            new_profile_id = f"{provider_name}:default"
            if new_profile_id in profiles:
                continue  # already set up

            profiles[new_profile_id] = {
                "type": "api_key",
                "provider": provider_name,
                "key": anthropic_key,
            }
            data["profiles"] = profiles
            auth_file.write_text(json.dumps(data, indent=2) + "\n")
            print(f"  Copied Anthropic API key to {provider_name} in {agent_dir.name}")
            copied = True
        except Exception as e:
            print(f"  WARNING: Failed to update {auth_file}: {e}")

    if not copied:
        print(f"  WARNING: No Anthropic API key found to copy. Run: openclaw agents add <id>")


def _setup_openclaw(args: argparse.Namespace) -> None:
    """Configure OpenClaw to route through the security proxy."""
    host = args.host or "127.0.0.1"
    port = args.port or 9920
    model = args.model or "claude-sonnet-4-20250514"
    provider_name = "anthropic-secured"
    base_url = f"http://{host}:{port}/anthropic"

    print(f"Configuring OpenClaw to use security proxy at {base_url}")
    print()

    # Step 1: Register the custom provider with a models array
    provider_json = (
        f'{{"baseUrl":"{base_url}",'
        f'"api":"anthropic-messages",'
        f'"models":[{{"id":"{model}","name":"Claude (secured)"}}]}}'
    )
    cmd1 = ["openclaw", "config", "set", f"models.providers.{provider_name}", provider_json]

    # Step 2: Set as default model
    model_id = f"{provider_name}/{model}"
    cmd2 = ["openclaw", "config", "set", "agents.defaults.model.primary", model_id]

    for cmd in [cmd1, cmd2]:
        print(f"  $ {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"  ERROR: {result.stderr.strip()}")
            sys.exit(1)
        if result.stdout.strip():
            print(f"  {result.stdout.strip()}")

    # Step 3: Copy Anthropic API key to the new provider in auth profiles
    _copy_auth_profile(provider_name)

    # Step 4: Disable the shim plugin (proxy replaces it)
    disable_cmd = ["openclaw", "config", "set", "plugins.entries.openclaw-security.enabled", "false"]
    print(f"  $ {' '.join(disable_cmd)}")
    result = subprocess.run(disable_cmd, capture_output=True, text=True)
    if result.returncode == 0:
        if result.stdout.strip():
            print(f"  {result.stdout.strip()}")
    else:
        print(f"  NOTE: Could not disable shim plugin — if it's loaded, events may be double-counted.")

    print()
    print("Done. OpenClaw will now route all Anthropic API traffic through the proxy.")
    print(f"  Provider:  {provider_name}")
    print(f"  Model:     {model_id}")
    print(f"  Proxy URL: {base_url}")
    print()
    print("Start the proxy with:")
    print(f"  openclaw-security --mode proxy -c <config.yaml>")


def _remove_auth_profile(provider_name: str) -> None:
    """Remove the secured provider from all agent auth profiles."""
    agents_dir = Path.home() / ".openclaw" / "agents"
    if not agents_dir.is_dir():
        return

    profile_id = f"{provider_name}:default"
    for agent_dir in agents_dir.iterdir():
        auth_file = agent_dir / "agent" / "auth-profiles.json"
        if not auth_file.exists():
            continue
        try:
            data = json.loads(auth_file.read_text())
            profiles = data.get("profiles", {})
            if profile_id in profiles:
                del profiles[profile_id]
                data["profiles"] = profiles
                auth_file.write_text(json.dumps(data, indent=2) + "\n")
                print(f"  Removed {provider_name} auth from {agent_dir.name}")
        except Exception as e:
            print(f"  WARNING: Failed to update {auth_file}: {e}")


def _revert_openclaw(args: argparse.Namespace) -> None:
    """Revert OpenClaw to use Anthropic directly."""
    model = args.model or "claude-sonnet-4-20250514"
    model_id = f"anthropic/{model}"

    print("Reverting OpenClaw to use Anthropic directly")
    print()

    # Reset the model to standard anthropic provider
    cmd1 = ["openclaw", "config", "set", "agents.defaults.model.primary", model_id]
    # Remove the custom provider
    cmd2 = ["openclaw", "config", "unset", "models.providers.anthropic-secured"]

    for cmd in [cmd1, cmd2]:
        print(f"  $ {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"  ERROR: {result.stderr.strip()}")
        if result.stdout.strip():
            print(f"  {result.stdout.strip()}")

    _remove_auth_profile("anthropic-secured")

    # Re-enable the shim plugin
    enable_cmd = ["openclaw", "config", "set", "plugins.entries.openclaw-security.enabled", "true"]
    print(f"  $ {' '.join(enable_cmd)}")
    result = subprocess.run(enable_cmd, capture_output=True, text=True)
    if result.stdout.strip():
        print(f"  {result.stdout.strip()}")

    print()
    print(f"Done. OpenClaw now uses anthropic/{model} directly.")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="openclaw-security",
        description="OpenClaw Security Platform",
    )
    sub = parser.add_subparsers(dest="command")

    # --- serve (default when no subcommand) ---
    serve_parser = sub.add_parser("serve", help="Start the evaluation server or proxy")
    serve_parser.add_argument("-c", "--config", help="Path to config YAML")
    serve_parser.add_argument(
        "--mode",
        choices=["server", "proxy"],
        default="server",
        help="server = shim eval endpoint; proxy = Anthropic API reverse proxy",
    )
    serve_parser.add_argument("--host", default=None)
    serve_parser.add_argument("--port", type=int, default=None)
    serve_parser.add_argument("--socket", default=None, help="Unix socket path")
    serve_parser.add_argument("--log-level", default="info")

    # --- setup ---
    setup_parser = sub.add_parser(
        "setup-openclaw",
        help="Configure OpenClaw to route through the security proxy",
    )
    setup_parser.add_argument("--host", default="127.0.0.1", help="Proxy host (default: 127.0.0.1)")
    setup_parser.add_argument("--port", type=int, default=9920, help="Proxy port (default: 9920)")
    setup_parser.add_argument("--model", default="claude-sonnet-4-20250514", help="Claude model ID")

    # --- revert ---
    revert_parser = sub.add_parser(
        "revert-openclaw",
        help="Revert OpenClaw to use Anthropic directly (bypass proxy)",
    )
    revert_parser.add_argument("--model", default="claude-sonnet-4-20250514", help="Claude model ID")

    # Check if the first positional arg is a known subcommand.
    # If not, fall back to server.py:main() for backward compat
    # (e.g. `openclaw-security -c config.yaml --mode proxy`).
    subcommands = {"serve", "setup-openclaw", "revert-openclaw"}
    has_subcommand = any(arg in subcommands for arg in sys.argv[1:])

    if not has_subcommand:
        from openclaw_security.server import main as server_main
        server_main()
        return

    args = parser.parse_args()

    if args.command == "serve":
        _run_server(args)
    elif args.command == "setup-openclaw":
        _setup_openclaw(args)
    elif args.command == "revert-openclaw":
        _revert_openclaw(args)


if __name__ == "__main__":
    main()
