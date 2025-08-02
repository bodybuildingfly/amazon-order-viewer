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
# Install dependencies into a temporary local folder for easy copying later
RUN pip install --no-cache-dir --target=/app/wheels -r requirements.txt


# --- Stage 2: Final Production Image ---
# Start from a minimal, secure Python image.
FROM python:3.12-slim

WORKDIR /app

# Create a non-root user for security
RUN useradd --create-home appuser
USER appuser

# Copy installed Python packages from the builder stage
COPY --from=builder /app/wheels /usr/local/lib/python3.12/site-packages

# CHANGED: Copy the contents of the backend folder directly into the app's root
COPY --from=builder /app/backend .

# Copy the built static frontend files
COPY --from=builder /app/frontend/build ./build

# Expose the port the app will run on
EXPOSE 5001

# The command to run the application using a production-grade Gunicorn server
# CHANGED: The entry point is now just app:app
CMD ["gunicorn", "--bind", "0.0.0.0:5001", "app:app"]