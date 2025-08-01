# backend/run.py
from amazon_viewer import create_app

app = create_app()

if __name__ == "__main__":
    # This allows running the app directly for debugging if needed,
    # but Gunicorn/Flask CLI will be the primary entry point.
    app.run(host='0.0.0.0', port=5001)
