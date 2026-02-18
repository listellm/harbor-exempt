# Build stage - install Python dependencies
FROM python:3.13.7-slim AS builder

WORKDIR /app

RUN pip install --no-cache-dir --upgrade pip

COPY requirements.txt .

# Install only from pre-built binary wheels to avoid compilation timeouts
RUN pip install --no-cache-dir --only-binary :all: --target=/app/deps -r requirements.txt

# Runtime stage
FROM python:3.13.7-slim

# Apply security patches to base image packages and pip
RUN apt-get update && \
    apt-get upgrade -y && \
    rm -rf /var/lib/apt/lists/* && \
    pip install --no-cache-dir --upgrade pip

# Create non-root user
RUN groupadd --system --gid 65532 appuser \
    && useradd --system --uid 65532 --gid appuser --no-create-home appuser

WORKDIR /app

# Copy installed dependencies from builder
COPY --from=builder /app/deps /app/deps

# Copy application code
COPY app/ ./app/

RUN chown -R appuser:appuser /app

USER appuser

ENV PYTHONPATH=/app/deps

EXPOSE 8000

CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--timeout-graceful-shutdown", "60"]
