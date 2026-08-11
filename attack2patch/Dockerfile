FROM python@sha256:229a2c5bfa27522db7815ea81f9bed70af17ccb9de9fc7ad142b1877b5830d36

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN useradd --create-home --uid 10001 autopatch
WORKDIR /app

COPY pyproject.toml constraints.txt README.md ./
COPY src ./src
RUN pip install --no-cache-dir --constraint constraints.txt .

COPY config ./config
COPY rules ./rules
COPY schemas ./schemas
COPY runbooks ./runbooks

RUN mkdir -p /app/.autopatch && chown autopatch:autopatch /app/.autopatch

USER autopatch
ENTRYPOINT ["autopatch"]
CMD ["--help"]
