#!/usr/bin/env python3
"""Athena CLI entrypoint. Plugins exec this binary. Scan logic lives in pkg/."""

from pkg.cli import main


if __name__ == "__main__":
    raise SystemExit(main())
