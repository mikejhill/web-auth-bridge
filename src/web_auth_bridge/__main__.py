"""Application entry point."""

from __future__ import annotations

import logging
import sys

from web_auth_bridge.cli import cli_main
from web_auth_bridge.exceptions import WebAuthBridgeError

logger = logging.getLogger(__name__)


def main() -> None:
    """Run the CLI with error handling."""
    logging.basicConfig(
        level=logging.WARNING,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )
    try:
        sys.exit(cli_main())
    except WebAuthBridgeError as exc:
        logger.error("%s", exc)
        sys.exit(1)


if __name__ == "__main__":
    main()
