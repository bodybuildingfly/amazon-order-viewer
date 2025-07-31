# Dockerfile
# Multi-stage build for a lean and secure production image.

# --- Stage 1: Build the React Frontend ---
FROM node:20-alpine AS frontend-builder

WORKDIR /app/frontend

# Copy package files and install dependencies
COPY frontend/package*.json ./
RUN npm install

# Copy the rest of the frontend source code
COPY frontend/ ./

# Build the static files
RUN npm run build

# --- Stage 2: Build the Python Backend ---
FROM python:3.12-slim AS backend-builder

WORKDIR /app

# Install system dependencies needed for Python packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libjpeg-dev \
    zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python packages
COPY backend/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy the backend source code
COPY backend/ ./

# --- Stage 3: Final Production Image ---
FROM python:3.12-slim

WORKDIR /app

# Create a non-root user for security
RUN useradd --create-home appuser
USER appuser

# Copy installed Python packages from the backend-builder stage
COPY --from=backend-builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
# Copy the backend application code
COPY --from=backend-builder /app ./

# Copy the built static frontend files from the frontend-builder stage
COPY --from=frontend-builder /app/frontend/build ./build

# Expose the port the app will run on
EXPOSE 5001

# Command to run the application using a production-grade server like Gunicorn
# We will add Gunicorn to requirements.txt in the next step.
CMD ["gunicorn", "--bind", "0.0.0.0:5001", "app:app"]