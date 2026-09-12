# ==============================================================================
# Stage 1: Build & Dependency Installation
# ==============================================================================
FROM python:3.12-slim AS builder

WORKDIR /build

# Install build dependencies for compiled packages (e.g. cryptography, bcrypt)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# ==============================================================================
# Stage 2: Minimal Production Runtime
# ==============================================================================
FROM python:3.12-slim AS runner

WORKDIR /app

# Install curl for container HEALTHCHECK
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy installed Python packages from builder stage
COPY --from=builder /install /usr/local

# Create non-root user and group
RUN groupadd -r -g 10001 mcpuser && \
    useradd -r -u 10001 -g mcpuser -d /app -s /sbin/nologin mcpuser

# Create key and data directories with correct permissions
RUN mkdir -p /app/.keys /app/data && \
    chown -R mcpuser:mcpuser /app

# Copy runtime application code only (tests, git, venv omitted via .dockerignore)
COPY --chown=mcpuser:mcpuser src_py/ /app/src_py/
COPY --chown=mcpuser:mcpuser public/ /app/public/
COPY --chown=mcpuser:mcpuser supabase/ /app/supabase/

# Switch to non-root user
USER mcpuser

# Environment variables with production defaults
ENV PORT=3000 \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    WEB_CONCURRENCY=2

EXPOSE 3000

# Container healthcheck hitting the public /health endpoint
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:${PORT}/health || exit 1

# Production entrypoint: uvicorn binding 0.0.0.0, tuned via WEB_CONCURRENCY
CMD ["sh", "-c", "uvicorn src_py.main:app --host 0.0.0.0 --port ${PORT} --workers ${WEB_CONCURRENCY}"]
