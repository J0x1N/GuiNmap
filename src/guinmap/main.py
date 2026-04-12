"""CLI entry point for the desktop application."""

from guinmap.app import run


def main() -> int:
    return run()


if __name__ == "__main__":
    raise SystemExit(main())
