FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN useradd --create-home --uid 10001 autopatch
WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir .

COPY config ./config
COPY rules ./rules
COPY schemas ./schemas
COPY runbooks ./runbooks

RUN mkdir -p /app/.autopatch && chown autopatch:autopatch /app/.autopatch

USER autopatch
ENTRYPOINT ["autopatch"]
CMD ["--help"]
