# Use Python 3.12 slim image for smaller size
FROM python:3.12-slim

# Note: .dockerignore is symlinked to .gitignore for unified exclusion rules

# Set working directory
WORKDIR /app

# Install uv for faster dependency management
# https://github.com/astral-sh/uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    UV_SYSTEM_PYTHON=1 \
    PORT=3000

# Copy dependency files and README first for better layer caching
COPY pyproject.toml README.md ./

# Copy the application source code (needed for editable install)
COPY src/ ./src/

# Install dependencies using uv
RUN uv pip install -e .

# Create directory for Garmin tokens
RUN mkdir -p /root/.garminconnect && \
    chmod 700 /root/.garminconnect

# Remote MCP deployment runs over HTTP/SSE on the port given via $PORT.
EXPOSE ${PORT}

# Set the entrypoint to run the HTTP wrapper
ENTRYPOINT ["garmin-mcp-http"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import os, urllib.request; urllib.request.urlopen('http://127.0.0.1:%s/health' % os.environ.get('PORT', '3000'), timeout=3)"
