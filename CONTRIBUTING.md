# Contributing

Thanks for helping improve Exif Killer.

## Development Setup

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -e .[dev]
```

## Core Workflow

1. Add or update tests for the behavior you touch.
2. Run `pytest`.
3. Run `ruff check .`.
4. Run `mypy`.
5. Keep the tool offline-first and deterministic.

## Contribution Guidelines

- Prefer changes that improve transparency and verification.
- Keep the GUI and CLI on the same shared service layer.
- Do not add telemetry or cloud-only behavior.
- Document risky assumptions and format-specific limitations.
- Preserve Windows support for the alpha line.

## Pull Requests

Good pull requests usually include:

- a short description of the user-visible change
- any security or compatibility tradeoffs
- test coverage for the new behavior
- updated docs if commands, report shape, or supported formats changed
