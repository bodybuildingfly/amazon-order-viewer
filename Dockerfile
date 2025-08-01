# Dockerfile
# This production Dockerfile builds the application by cloning it from GitHub.

# --- Stage 1: Source Code Retrieval & Build ---
# We use a full-featured image that includes git and build tools.
FROM python:3.12-bookworm AS builder

# Install Node.js and npm
RUN apt-get update && apt-get install -y --no-install-recommends nodejs npm

WORKDIR /app

# Clone the repository from GitHub
RUN git clone https://github.com/bodybuildingfly/amazon-order-viewer.git .

# --- Build Frontend ---
WORKDIR /app/frontend
RUN npm install
RUN npm run build

# --- Install Backend Dependencies ---
WORKDIR /app/backend
# Install dependencies normally into the builder's standard Python environment
RUN pip install --no-cache-dir -r requirements.txt


# --- Stage 2: Final Production Image ---
# Start from a minimal, secure Python image.
FROM python:3.12-slim

# Install the common runtime dependencies for the Pillow library
RUN apt-get update && apt-get install -y --no-install-recommends \
    libjpeg62-turbo \
    libopenjp2-7 \
    libtiff6 \
    libwebp7 \
    libfreetype6 \
    libxcb1 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Create a non-root user for security
RUN useradd --create-home appuser

# Copy installed Python packages from the builder stage
COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages

# Copy the Python executables (like gunicorn) from the builder stage
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy the backend application code
COPY --from=builder /app/backend ./backend

# Copy the built static frontend files
COPY --from=builder /app/frontend/build ./build

# Change ownership of the app directory to the non-root user
RUN chown -R appuser:appuser /app

# Switch to the non-root user
USER appuser

EXPOSE 5001

# UPDATED: Use the 'gevent' worker class to enable streaming
CMD ["gunicorn", "--worker-class", "gevent", "--bind", "0.0.0.0:5001", "backend.app:app"]
