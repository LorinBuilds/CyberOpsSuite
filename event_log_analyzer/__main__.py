"""Allow ``python -m event_log_analyzer`` to run the command-line interface."""

from event_log_analyzer.cli.main import main

if __name__ == "__main__":
    raise SystemExit(main())
