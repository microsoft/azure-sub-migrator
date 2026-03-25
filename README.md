# Azure Sub Migrator

**Azure Sub Migrator – Azure Tenant-to-Tenant Subscription Migration Tool**

[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-47%20passed-brightgreen.svg)](#running-tests)

A modular, open-source tool that helps you migrate Azure subscriptions and resources from one Microsoft Entra (Azure AD) tenant to another — via **CLI** or a **Web UI**.

---

## Features

| Capability | Description |
|---|---|
| **Resource scanning** | Identify resources impacted by a tenant transfer with timing & required actions |
| **Pre-transfer readiness check** | Detect blockers (AKS, SQL Entra auth) and warnings before you transfer |
| **RBAC export / import** | Back up and restore role assignments, custom roles, and managed identities |
| **Interactive checklist** | Step-by-step web-based migration checklist |
| **PDF & Excel reports** | Branded, exportable reports for stakeholders and change-advisory boards |
| **Migration plan** | Human-readable Markdown + machine-readable JSON plan |
| **IaC generation** | Export ARM, Bicep, and Terraform templates for non-movable resources |
| **Subscription transfer** | Optionally initiate the "change directory" process |
| **Multi-tenant auth** | Works across any Azure tenant — CLI, Service Principal, or Managed Identity |

## Architecture

```
azure_sub_migrator/
├── __init__.py          # Package metadata
├── cli.py               # Click-based CLI entry point
├── auth.py              # Authentication (CLI / SP / MI)
├── scanner.py           # Resource enumeration & classification
├── iac_generator.py     # ARM / Bicep / Terraform export
├── migration_plan.py    # Orchestrator – scan → classify → export → report
├── transfer.py          # Subscription transfer ("change directory")
├── rbac.py              # Role assignments & managed identities
├── reporter.py          # Markdown report writer
├── report_export.py     # PDF & Excel report generation
├── readiness.py         # Pre-transfer readiness checks
├── config.py            # YAML / env-var configuration
├── constants.py         # Non-movable resource types & suggested actions
├── exceptions.py        # Custom exception hierarchy
└── logger.py            # Centralized logging
```

## Quick Start

### Prerequisites

- Python 3.9+
- Azure CLI (`az`) — logged in to the **source** tenant
- *(optional)* `aztfexport` for Terraform exports
- *(optional)* `azcopy` for data migration

### Installation

```bash
git clone https://github.com/microsoft/azure-sub-migrator.git
cd azure-sub-migrator

# Create a virtual environment
python -m venv .venv
.venv\Scripts\activate      # Windows
# source .venv/bin/activate  # macOS/Linux

# Install in editable mode with dev dependencies
pip install -e ".[dev]"
```

### Usage

```bash
# Verify authentication
azure-sub-migrator login

# List subscriptions
azure-sub-migrator list-subs

# Scan a subscription for movable vs non-movable resources
azure-sub-migrator scan -s <subscription-id>

# Generate a full migration plan with IaC templates
azure-sub-migrator plan -s <subscription-id> -t <target-tenant-id>

# Initiate subscription transfer (dry-run first!)
azure-sub-migrator transfer -s <subscription-id> -t <target-tenant-id> --dry-run
```

### Configuration

You can provide settings via:

1. **YAML file** — `--config config.yaml` (see `samples/sample_config.yaml`)
2. **Environment variables** — prefixed with `AZ_MIGRATE_` (e.g. `AZ_MIGRATE_SUBSCRIPTION_ID`)
3. **CLI flags** — override everything (e.g. `--tenant-id`, `--auth-method`)

## Web UI

Azure Sub Migrator includes a full Flask + Bootstrap 5 web dashboard.

### Setup

1. [Register an Entra ID app](https://learn.microsoft.com/en-us/entra/identity-platform/quickstart-register-app) with a Web redirect URI of `http://localhost:5000/auth/callback`.
2. Copy `.env.example` to `.env` and fill in your credentials.
3. Start the server:

```bash
# Set environment variables (PowerShell)
$env:ENTRA_CLIENT_ID = "<your-client-id>"
$env:ENTRA_CLIENT_SECRET = "<your-client-secret>"
$env:FLASK_SECRET_KEY = [guid]::NewGuid().ToString()

python -m web.wsgi
```

4. Open http://localhost:5000 and sign in with your Microsoft account.

### Web Features

- 📊 **Dashboard** — view and scan subscriptions
- 🔍 **Resource scanning** — live progress with polling
- ✅ **Interactive checklist** — step-by-step migration guide
- 🛡️ **RBAC export** — download role assignments as JSON
- ⚡ **Readiness check** — detect blockers before transfer
- 📄 **PDF report** — branded, multi-page migration report
- 📗 **Excel report** — 3-sheet workbook with filters and summary

### Running Tests

```bash
pytest -v --cov=azure_sub_migrator
```

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Code of Conduct

This project has adopted the
[Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the
[Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any
additional questions or comments.

## Security

If you discover a security vulnerability, please see [SECURITY.md](SECURITY.md)
for reporting instructions. **Do not open a public GitHub issue for
security vulnerabilities.**

## Trademarks

This project may contain trademarks or logos for projects, products, or services.
Authorized use of Microsoft trademarks or logos is subject to and must follow
[Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general).
Use of Microsoft trademarks or logos in modified versions of this project must
not cause confusion or imply Microsoft sponsorship. Any use of third-party
trademarks or logos are subject to those third-party's policies.

## License

[MIT](LICENSE)
