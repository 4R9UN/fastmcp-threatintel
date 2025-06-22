# Multi-stage build for production-ready container
FROM python:3.10-slim as builder

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install UV
RUN pip install uv

# Create and set working directory
WORKDIR /app

# Copy dependency files
COPY pyproject.toml uv.lock ./

# Create virtual environment and install dependencies
RUN uv venv /opt/venv && \
    /opt/venv/bin/python -m pip install --upgrade pip && \
    uv sync --frozen

# Production stage
FROM python:3.10-slim as production

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/opt/venv/bin:$PATH"

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -r threatintel \
    && useradd -r -g threatintel threatintel

# Copy virtual environment from builder stage
COPY --from=builder /opt/venv /opt/venv

# Create app directory and copy source code
WORKDIR /app
COPY src/ ./src/
COPY README.md ./

# Set ownership to non-root user
RUN chown -R threatintel:threatintel /app

# Switch to non-root user
USER threatintel

# Expose port for web interface (if needed)
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import sys; sys.exit(0)"

# Default command
CMD ["python", "-m", "src.threatintel.server"]

# Alternative entry points
LABEL org.opencontainers.image.title="FastMCP ThreatIntel"
LABEL org.opencontainers.image.description="AI-Powered Threat Intelligence Analysis Tool"
LABEL org.opencontainers.image.source="https://github.com/4R9UN/fastmcp-threatintel"
LABEL org.opencontainers.image.licenses="Apache-2.0"