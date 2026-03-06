#!/bin/bash
# Azure App Service startup script
# Dependencies are installed during the Oryx build step (SCM_DO_BUILD_DURING_DEPLOYMENT=true).

gunicorn --bind=0.0.0.0:8000 --timeout 600 --workers 2 web.wsgi:app
