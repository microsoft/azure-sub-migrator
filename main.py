# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

#!/usr/bin/env python3
"""Azure Tenant-to-Tenant Migration CLI — entry point.

Usage:
    python main.py --help
    python main.py login
    python main.py list-subs
    python main.py scan -s <subscription-id>
    python main.py plan -s <subscription-id> -t <target-tenant-id>
    python main.py transfer -s <subscription-id> -t <target-tenant-id> [--dry-run]
"""

from azure_sub_migrator.cli import main

if __name__ == "__main__":
    main()
