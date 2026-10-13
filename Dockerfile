# Vigil — runs the CLI in a minimal, non-root container.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# uv for fast, locked installs
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

COPY pyproject.toml README.md LICENSE ./
COPY src ./src

RUN uv pip install --system . && \
    useradd --system --uid 10001 vigil && \
    mkdir -p /data/.vigil && chown -R vigil /data

USER vigil
WORKDIR /data

ENTRYPOINT ["vigil"]
CMD ["--help"]
