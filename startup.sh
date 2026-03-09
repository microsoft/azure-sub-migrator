#!/bin/bash
# Azure App Service startup script
# Dependencies are installed during the Oryx build step (SCM_DO_BUILD_DURING_DEPLOYMENT=true).
#
# IMPORTANT: Use --workers 1 --threads 4 (not --workers 2) because the app
# stores background-task state in-memory.  Multiple worker *processes*
# each get their own memory space, so a scan started in worker A is
# invisible to worker B.  Threads share memory within a single process.

gunicorn --bind=0.0.0.0:8000 --timeout 600 --workers 1 --threads 4 web.wsgi:app
