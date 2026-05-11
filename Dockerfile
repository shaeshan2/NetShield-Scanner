# NetShield Scanner — defensive TCP inventory tool (AUTHORIZED scopes only).
# See README.md ethical use disclaimer before deploying or running scans.

FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONIOENCODING=UTF-8

WORKDIR /app

# Writable bind mount: host ./reports must allow this UID (see README Docker usage).
RUN useradd --create-home --no-log-init --uid 65532 --shell /usr/sbin/nologin netshield \
    && mkdir -p /app/reports

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

COPY main.py ./
COPY scanner ./scanner/
COPY templates ./templates/

RUN chown -R netshield:netshield /app

USER netshield

ENTRYPOINT ["python", "main.py"]
CMD ["--help"]
