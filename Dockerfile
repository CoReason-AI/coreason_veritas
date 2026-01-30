# Stage 1: Builder
FROM python:3.12-slim AS builder

# Install build dependencies
RUN pip install --no-cache-dir build==1.3.0

# Set the working directory
WORKDIR /app

# Copy the project files
COPY pyproject.toml .
COPY src/ ./src/
COPY README.md .
COPY LICENSE .

# Build the wheel
RUN python -m build --wheel --outdir /wheels


# Stage 2: Runtime
FROM python:3.12-slim AS runtime

# Create a non-root user
RUN useradd --create-home --shell /bin/bash appuser
USER appuser

# Add user's local bin to PATH
ENV PATH="/home/appuser/.local/bin:${PATH}"

# Set the working directory
WORKDIR /home/appuser/app

# Copy the wheel from the builder stage
COPY --from=builder /wheels /wheels

# Install the application wheel
RUN pip install --no-cache-dir /wheels/*.whl

# Pre-download the Spacy model during the BUILD phase
RUN python -m spacy download en_core_web_lg

ENV OTEL_SERVICE_NAME=coreason-veritas-svc

CMD ["uvicorn", "coreason_veritas.server:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
