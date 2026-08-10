FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN groupadd --system honeypot && useradd --system --gid honeypot --home /app honeypot

COPY pyproject.toml README.md ./
COPY app ./app
COPY templates ./templates
COPY static ./static
COPY docs ./docs

RUN pip install --no-cache-dir . && mkdir -p /app/data && chown -R honeypot:honeypot /app

USER honeypot

EXPOSE 8000 2222

CMD ["python", "-m", "app.main"]
