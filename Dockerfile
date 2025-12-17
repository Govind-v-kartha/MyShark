# syntax=docker/dockerfile:1
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

# System deps (build essentials for some wheels if needed)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy project files
COPY pyproject.toml README.md /app/
COPY myshark /app/myshark
COPY templates /app/templates
COPY web_app.py /app/web_app.py

# Install project and runtime deps
RUN pip install --upgrade pip setuptools wheel \
    && pip install -e . \
    && pip install uvicorn

EXPOSE 8000

CMD ["uvicorn", "web_app:app", "--host", "0.0.0.0", "--port", "8000"]
