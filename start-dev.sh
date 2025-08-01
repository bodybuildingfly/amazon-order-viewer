#!/bin/sh

# start-dev.sh
# This script starts both the backend and frontend servers for development.

echo "Starting development servers..."

# Start the Flask backend API in the background
# We use --app to specify the location of our Flask application file.
echo "Starting Flask backend server on port 5001..."
flask --app backend/app.py run --host=0.0.0.0 --port=5001 &

# Start the React frontend development server in the foreground
echo "Starting React frontend server on port 3000..."
npm start --prefix frontend