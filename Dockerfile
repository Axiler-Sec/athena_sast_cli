# Thin CLI image. No secrets. Inject env at runtime.
# Never COPY .env. Never --build-arg ATHENA_API_KEY.
FROM python:3.12-slim

WORKDIR /opt/athena
COPY pyproject.toml README.md LICENSE athena.py ./
COPY pkg ./pkg

RUN python3 -m pip install --no-cache-dir --root-user-action=ignore . \
    && useradd --create-home --uid 10001 --shell /usr/sbin/nologin athena \
    && mkdir -p /src \
    && chown athena:athena /src

WORKDIR /src
USER athena
ENTRYPOINT ["athena"]
