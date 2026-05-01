# Use the official Python slim image for smaller size & smaller attack surface
FROM python:3.12-slim

# Set workdir inside the container
WORKDIR /app

# Security best practice: don't run as root
# We create a non-root user for the app to run under
RUN groupadd --gid 1000 appuser && \
    useradd --uid 1000 --gid 1000 --create-home --shell /bin/bash appuser

# Install system dependencies needed for psycopg and healthchecks
# Then clean up apt cache to keep image small
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        curl \
        && rm -rf /var/lib/apt/lists/*

# Copy requirements first (Docker layer caching: this layer only rebuilds
# if requirements.txt changes, so day-to-day code changes don't re-install deps)
COPY requirements.txt .

# Upgrade pip and install Python deps
# --no-cache-dir keeps image small
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy the rest of the app
COPY . .

# Make sure files are owned by the non-root user
RUN chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

# The port the app listens on inside the container
EXPOSE 8000

# Healthcheck — Docker can use this to know if the app is alive
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl --fail http://127.0.0.1:8000/health || exit 1

# Run the app with uvicorn
# --host 0.0.0.0 means "listen on all interfaces inside the container"
# (necessary because Docker Compose port mapping won't reach 127.0.0.1)
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]