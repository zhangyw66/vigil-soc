# Contributing to Vigil

Thanks for helping build the analyst that never sleeps. All contributions — code, docs, benchmark
samples, bug reports — are welcome.

## Code of Conduct

Please read [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). Be kind; this project serves defenders.

## Project scope

Vigil is **defensive**. It analyzes security telemetry and produces triage decisions, evidence
chains, and detection rules. Contributions that generate offensive payloads or target unauthorized
systems are out of scope and will be rejected.

## Getting started

```bash
git clone https://github.com/yourname/vigil
cd vigil
uv sync --extra dev          # or: python -m venv .venv && .venv/bin/pip install -e ".[dev]"
uv run pytest                # run tests
uv run ruff check src tests  # lint
uv run mypy src              # type check
```

## Where to contribute

- **Connectors** (`src/vigil/ingest/plugins/`): add a new data source. Implement the `Connector`
  protocol and register via an entry point.
- **Detection rules** (`src/vigil/pipeline/`): deterministic scoring rules — the highest-leverage
  place to help.
- **Benchmark data** (`tests/fixtures/`): synthetic, anonymized alerts with gold labels for the
  eval harness. Never submit real customer data.
- **Docs & research**: `docs/security-model.md` and the prompt-injection test cases are a
  first-class research surface.

## Pull request checklist

- [ ] `uv run ruff check src tests` passes
- [ ] `uv run mypy src` passes
- [ ] `uv run pytest` passes
- [ ] New behavior is covered by a test
- [ ] No real/private data added; synthetic samples labeled as such
- [ ] CHANGELOG entry (if user-facing)

## Releases

Monthly minor releases, semantic versioning. Maintainers merge release PRs.
