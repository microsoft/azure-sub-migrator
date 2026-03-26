# Contributing to Azure Sub Migrator

Thanks for your interest in contributing!

This project welcomes contributions and suggestions. Most contributions require
you to agree to a Contributor License Agreement (CLA) declaring that you have
the right to, and actually do, grant us the rights to use your contribution.
For details, visit <https://cla.opensource.microsoft.com>.

When you submit a pull request, a CLA bot will automatically determine whether
you need to provide a CLA and decorate the PR appropriately (e.g., status check,
comment). Simply follow the instructions provided by the bot. You will only need
to do this once across all repos using our CLA.

This project has adopted the
[Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the
[Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any
additional questions or comments.

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
pytest -v --cov=azure_sub_migrator
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
mypy azure_sub_migrator/
```

## What to Contribute

- 🐛 **Bug fixes** — always welcome
- 📖 **Documentation** — typos, examples, guides
- 🧪 **Tests** — improve coverage
- ✨ **New resource types** — add entries to `azure_sub_migrator/constants.py`
- 🌐 **Web UI improvements** — Bootstrap templates in `web/templates/`
- 🔌 **New features** — please open an issue first to discuss

## Adding a New Resource Type

If Azure adds a new resource type that requires special handling during tenant migration:

1. Add the resource type to `IMPACTED_RESOURCE_TYPES` in [azure_sub_migrator/constants.py](azure_sub_migrator/constants.py).
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

Be kind and respectful. This project follows the
[Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).

## Questions?

Open an issue or start a discussion — happy to help!
