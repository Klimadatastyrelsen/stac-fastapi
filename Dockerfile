FROM python:3.8-slim-bookworm AS production

# several pinned deps have no cp38 wheel and compile from source
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential \
    && apt-get upgrade -y \
    && rm -rf /var/lib/apt/lists/*

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY stac_fastapi /app/stac_fastapi
COPY stac-fastapi-sqlalchemy /app/stac-fastapi-sqlalchemy

# one pip invocation so the resolver cannot swap pypi stac-fastapi.* dists in over these
RUN pip install --no-cache-dir \
    -e ./stac_fastapi/types \
    -e ./stac_fastapi/api[oidc] \
    -e ./stac_fastapi/extensions \
    -e ./stac-fastapi-sqlalchemy[server]

EXPOSE 8081

CMD ["python", "-m", "uvicorn", "stac_fastapi.sqlalchemy.app:app", "--proxy-headers", "--host", "0.0.0.0", "--port", "8081", "--timeout-keep-alive", "65"]
