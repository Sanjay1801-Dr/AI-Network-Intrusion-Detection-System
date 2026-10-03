# ==============================================================================
# AI-Based Network Intrusion Detection System (NIDS) - Backend Container
# Phase 10: Production Configuration & Deployment Readiness
# ==============================================================================

FROM python:3.12-slim

# Prevent Python from writing .pyc bytecode and force unbuffered output
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install system dependencies for C extensions and health checks
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy backend source code, ML models, and pipelines
COPY backend/ ./backend/
COPY machine_learning/ ./machine_learning/
COPY machine-learning/ ./machine-learning/

# Expose FastAPI application port
EXPOSE 8000

# Health check using native Python standard library
HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/health')" || exit 1

# Start Uvicorn ASGI server
CMD ["uvicorn", "backend.app.main:app", "--host", "0.0.0.0", "--port", "8000"]
