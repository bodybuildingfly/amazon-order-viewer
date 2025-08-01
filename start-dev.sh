#!/bin/sh

# start-dev.sh
# This script starts both the backend and frontend servers for development.

# Exit immediately if a command exits with a non-zero status.
set -e

echo "Starting development servers..."

# UPDATED: Point to the new run.py entry point
echo "Starting Flask backend server on port 5001..."
flask --app backend/run.py run --host=0.0.0.0 --port=5001 &

# Give the backend a moment to start up before the frontend tries to connect
sleep 5

# Start the React frontend development server in the foreground
echo "Starting React frontend server on port 3000..."
npm start --prefix frontend