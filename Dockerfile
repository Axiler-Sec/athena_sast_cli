# Thin CLI image (Sonar scanner-cli model). No secrets. Inject env at runtime.
FROM python:3.12-slim

WORKDIR /opt/athena
COPY pyproject.toml README.md athena.py ./
COPY pkg ./pkg

RUN python3 -m pip install --no-cache-dir .

WORKDIR /src
ENTRYPOINT ["athena"]
