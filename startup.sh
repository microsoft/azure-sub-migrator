#!/bin/bash
# Azure App Service startup script
# This file is referenced in App Service → Configuration → Startup Command

# Install dependencies (already done during deployment, but belt-and-suspenders)
pip install --no-cache-dir -r requirements.txt

# Start gunicorn pointing at the Flask WSGI app
gunicorn --bind=0.0.0.0:8000 --timeout 600 --workers 2 web.wsgi:app
