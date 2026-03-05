"""WSGI entry point for the Flask web application.

Used by gunicorn / Azure App Service.
"""

from web.app import create_app

app = create_app()

if __name__ == "__main__":
    app.run(debug=True, port=5000)
