FROM python:3.12-slim
WORKDIR /app
RUN apt-get update \
    && apt-get install -y --no-install-recommends docker-cli docker-compose docker-buildx \
    && rm -rf /var/lib/apt/lists/*
COPY pyproject.toml .
COPY src ./src
COPY demo-app ./demo-app
COPY docker-compose.yml ./docker-compose.yml
RUN pip install --no-cache-dir ".[validation]"
ENV PYTHONPATH=/app/src
EXPOSE 8080
CMD ["python", "-m", "attack2patch.ui.api"]
