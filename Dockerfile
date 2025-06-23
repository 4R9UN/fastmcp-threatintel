# Multi-stage build for production-ready container
FROM python:3.11-slim AS builder

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

# Create and set working directory
WORKDIR /app

# Add cache bust
ARG CACHEBUST=1

# Copy dependency files and source code
COPY pyproject.toml README.md ./
COPY src/ ./src/

# Create virtual environment and install dependencies
RUN python -m venv /opt/venv && \
    /opt/venv/bin/pip install --upgrade pip && \
    /opt/venv/bin/pip install -e .

# Production stage
FROM python:3.11-slim AS production

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
COPY pyproject.toml README.md ./

# Install the package in production stage
RUN /opt/venv/bin/pip install -e .

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
CMD ["threatintel", "--help"]

# Container metadata and labels
LABEL org.opencontainers.image.title="🛡️ FastMCP ThreatIntel - Enterprise Threat Intelligence Platform"
LABEL org.opencontainers.image.description="🛡️ MCP AI Powered Threat Intelligence - Revolutionizing Cybersecurity | Built by Arjun Trivedi (4R9UN)"
LABEL org.opencontainers.image.source="https://github.com/4R9UN/fastmcp-threatintel"
LABEL org.opencontainers.image.url="https://github.com/4R9UN/fastmcp-threatintel"
LABEL org.opencontainers.image.documentation="https://4r9un.github.io/fastmcp-threatintel/"
LABEL org.opencontainers.image.licenses="Apache-2.0"
LABEL org.opencontainers.image.author="Arjun Trivedi (4R9UN) <arjuntrivedi42@yahoo.com>"
LABEL org.opencontainers.image.vendor="Roo Engineering"
LABEL org.opencontainers.image.version="0.2.5"
LABEL maintainer="Arjun Trivedi (4R9UN) <arjuntrivedi42@yahoo.com>"
LABEL org.opencontainers.image.created="2025-06-23"
LABEL org.opencontainers.image.revision="main"
LABEL org.label-schema.vcs-url="https://github.com/4R9UN/fastmcp-threatintel.git"
LABEL org.label-schema.docker.cmd="docker run -e VIRUSTOTAL_API_KEY=your_key -e OTX_API_KEY=your_key arjuntrivedi/4r9un:fastmcp-threatintel-latest analyze 8.8.8.8"