# Tenova

**Tenova – Azure Tenant-to-Tenant Migration Tool**

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
tenova/
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
git clone https://github.com/microsoft/tenova.git
cd tenova

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
tenova login

# List subscriptions
tenova list-subs

# Scan a subscription for movable vs non-movable resources
tenova scan -s <subscription-id>

# Generate a full migration plan with IaC templates
tenova plan -s <subscription-id> -t <target-tenant-id>

# Initiate subscription transfer (dry-run first!)
tenova transfer -s <subscription-id> -t <target-tenant-id> --dry-run
```

### Configuration

You can provide settings via:

1. **YAML file** — `--config config.yaml` (see `samples/sample_config.yaml`)
2. **Environment variables** — prefixed with `AZ_MIGRATE_` (e.g. `AZ_MIGRATE_SUBSCRIPTION_ID`)
3. **CLI flags** — override everything (e.g. `--tenant-id`, `--auth-method`)

## Web UI

Tenova includes a full Flask + Bootstrap 5 web dashboard.

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
pytest -v --cov=tenova
```

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

[MIT](LICENSE)
