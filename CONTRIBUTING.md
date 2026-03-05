# Contributing to Tenova

Thanks for your interest in contributing! 🎉

## Getting Started

1. **Fork** the repository and clone your fork.
2. Create a virtual environment and install dev dependencies:

   ```bash
   cd tenant-tenant-migration
   python -m venv .venv
   .venv\Scripts\activate        # Windows
   # source .venv/bin/activate   # macOS / Linux
   pip install -e ".[dev]"
   ```

3. Create a feature branch:

   ```bash
   git checkout -b feature/my-feature
   ```

## Development Workflow

### Running Tests

```bash
pytest -v --cov=tenova
```

All pull requests must pass the existing test suite. Please add tests for any new functionality.

### Code Style

We use **Ruff** for linting:

```bash
ruff check .
ruff format .
```

### Type Checking

```bash
mypy tenova/
```

## What to Contribute

- 🐛 **Bug fixes** — always welcome
- 📖 **Documentation** — typos, examples, guides
- 🧪 **Tests** — improve coverage
- ✨ **New resource types** — add entries to `tenova/constants.py`
- 🌐 **Web UI improvements** — Bootstrap templates in `web/templates/`
- 🔌 **New features** — please open an issue first to discuss

## Adding a New Resource Type

If Azure adds a new resource type that requires special handling during tenant migration:

1. Add the resource type to `IMPACTED_RESOURCE_TYPES` in [tenova/constants.py](tenova/constants.py).
2. Add the corresponding entry to `REQUIRED_ACTIONS` with timing, pre/post actions, and doc URL.
3. Add a test case in `tests/test_scanner.py`.
4. Submit a PR!

## Pull Request Guidelines

- Keep PRs focused — one feature or fix per PR.
- Include tests for new functionality.
- Update documentation if behaviour changes.
- Ensure all tests pass before submitting.
- Use descriptive commit messages.

## Code of Conduct

Be kind and respectful. We follow the [Contributor Covenant](https://www.contributor-covenant.org/version/2/1/code_of_conduct/).

## Questions?

Open an issue or start a discussion — happy to help!
