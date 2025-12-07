# Frontend build stage (optional)
FROM node:20-bullseye AS frontend-builder
WORKDIR /app/frontend
COPY frontend/package*.json ./
RUN npm install
COPY frontend/ ./
RUN npm run build

# Backend stage
FROM python:3.11-slim
ENV PYTHONUNBUFFERED=1
WORKDIR /app

# System deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    curl \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Poetry installation
RUN pip install --no-cache-dir poetry
RUN poetry config virtualenvs.create false

COPY pyproject.toml poetry.lock* README.md ./
COPY src ./src
RUN poetry install --only main --no-interaction --no-ansi
COPY templates ./templates
RUN mkdir -p scan_artifacts
COPY --from=frontend-builder /app/frontend/dist ./frontend/dist

EXPOSE 8000
CMD ["uvicorn", "clanker.main:app", "--host", "0.0.0.0", "--port", "8000"]
