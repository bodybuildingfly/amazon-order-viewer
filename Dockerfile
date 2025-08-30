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
# This command creates /app/wheels/ and also a subfolder /app/wheels/bin/
RUN pip install --no-cache-dir --target=/app/wheels -r requirements.txt

# --- Stage 2: Final Production Image ---
# Start from a minimal, secure Python image.
FROM python:3.12-slim

WORKDIR /app

# This makes sure the system can find executables in /usr/local/bin
ENV PATH="/usr/local/bin:${PATH}"

# CHANGED: Added zlib1g for robust PNG support via Pillow.
RUN apt-get update && apt-get install -y --no-install-recommends \
    libjpeg62-turbo \
    libopenjp2-7 \
    libtiff6 \
    zlib1g \
    libxcb1 \
    && rm -rf /var/lib/apt/lists/*

# Create a non-root user for security
RUN useradd --create-home appuser

# Create the output directory and give the non-root user ownership of it.
# This allows the amazon-orders library to write session files.
RUN mkdir /app/output && chown appuser:appuser /app/output

# Switch to the non-root user for the rest of the build and for runtime
USER appuser

# Copy installed Python packages (the library code) from the builder stage
COPY --from=builder /app/wheels /usr/local/lib/python3.12/site-packages

# Copy the executables (like gunicorn) from the builder stage
COPY --from=builder /app/wheels/bin /usr/local/bin

# Copy the backend application code
COPY --from=builder /app/backend .

# Copy the built static frontend files
COPY --from=builder /app/frontend/build ./build

# Expose the port the app will run on
EXPOSE 5001

# The command to run the application using a production-grade Gunicorn server
CMD ["gunicorn", "--bind", "0.0.0.0:5001", "--workers", "4", "--worker-class", "gevent", "--timeout", "120", "app:app"]