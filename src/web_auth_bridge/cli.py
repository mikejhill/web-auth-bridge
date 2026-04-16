"""CLI argument parsing and dispatch."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from web_auth_bridge.auth.cache import AuthCache


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse command-line arguments.

    Args:
        argv: Argument list (defaults to ``sys.argv[1:]``).

    Returns:
        Parsed namespace.
    """
    parser = argparse.ArgumentParser(
        prog="web-auth-bridge",
        description="Browser authentication bridge for HTTP APIs — diagnostics and cache management.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version="%(prog)s 0.1.0",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # cache-status
    status_parser = subparsers.add_parser(
        "cache-status",
        help="Show authentication cache status",
    )
    status_parser.add_argument(
        "cache_dir",
        type=Path,
        help="Path to the cache directory",
    )

    # cache-clear
    clear_parser = subparsers.add_parser(
        "cache-clear",
        help="Delete the authentication cache",
    )
    clear_parser.add_argument(
        "cache_dir",
        type=Path,
        help="Path to the cache directory",
    )

    return parser.parse_args(argv)


def run_cache_status(cache_dir: Path) -> int:
    """Display cache file info and expiry status.

    Args:
        cache_dir: Directory containing the auth cache.

    Returns:
        Exit code (0 for success, 1 for errors).
    """
    cache = AuthCache(cache_dir)
    result = cache.load()
    if result is None:
        print("No cache found.")
        return 1

    info = {
        "cache_file": str(cache.cache_file),
        "created_at": result.created_at.isoformat(),
        "expires_at": result.expires_at.isoformat() if result.expires_at else None,
        "is_expired": result.is_expired,
        "cookie_count": len(result.cookies),
        "token_keys": list(result.tokens.keys()),
        "local_storage_keys": list(result.local_storage.keys()),
    }
    print(json.dumps(info, indent=2))
    return 0


def run_cache_clear(cache_dir: Path) -> int:
    """Delete the auth cache.

    Args:
        cache_dir: Directory containing the auth cache.

    Returns:
        Exit code (0 for success, 1 for errors).
    """
    cache = AuthCache(cache_dir)
    cache.invalidate()
    print("Cache cleared.")
    return 0


def cli_main(argv: list[str] | None = None) -> int:
    """CLI entry point.

    Args:
        argv: Argument list (defaults to ``sys.argv[1:]``).

    Returns:
        Exit code.
    """
    args = parse_args(argv)

    if args.command == "cache-status":
        return run_cache_status(args.cache_dir)
    if args.command == "cache-clear":
        return run_cache_clear(args.cache_dir)

    # No command specified — show help
    parse_args(["--help"])
    return 0  # pragma: no cover


if __name__ == "__main__":
    sys.exit(cli_main())
