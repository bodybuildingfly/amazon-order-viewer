#!/bin/sh

# start-dev.sh
# This script starts both the backend and frontend servers for development.

echo "Starting development servers..."

# Start the Flask backend API with Gunicorn in the background
# We run gunicorn as a module to avoid PATH issues.
echo "Starting Flask backend server with Gunicorn on port 5001..."
python -m gunicorn --bind 0.0.0.0:5001 \
    --workers 1 \
    --worker-class gevent \
    --reload \
    --chdir backend \
    app:app &

# Start the React frontend development server in the foreground
echo "Starting React frontend server on port 3000..."
cd frontend && npm start