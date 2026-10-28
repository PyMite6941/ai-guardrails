FROM python:3.11-slim

WORKDIR /app

# Install curl for the model-container healthcheck / outside-model probes.
RUN apt-get update && apt-get install -y --no-install-recommends curl && \
    rm -rf /var/lib/apt/lists/*

# Guardrail engine (stdlib only — no pip deps needed)
COPY guardrail.py /app/guardrail.py
COPY guardrail_server.py /app/guardrail_server.py
COPY outer_monitor.py /app/outer_monitor.py
COPY policies /app/policies
COPY scripts /app/scripts
COPY web /app/web
COPY tmux /app/tmux
COPY README.md /app/README.md
COPY LICENSE /app/LICENSE

ENV GUARDRAIL_HOST=0.0.0.0
ENV GUARDRAIL_PORT=8083
ENV AI_GUARDRAILS_LOG_DIR=/app/logs
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Outer monitor / outside-model wiring (all optional, off by default)
ENV OUTSIDE_MODEL_ENABLED=0
ENV OUTSIDE_MODEL_BASE_URL=http://localhost:11434
ENV OUTSIDE_MODEL_MODEL=qwen2.5:1.5b
ENV OUTSIDE_MODEL_ENDPOINT=generate
ENV OUTSIDE_MODEL_TIMEOUT=30

RUN chmod +x /app/scripts/kill-switch.sh /app/tmux/guardrail-tmux.sh && \
    mkdir -p /app/logs /app/policies/pages

EXPOSE 8083

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8083/api/health', timeout=5)" || exit 1

CMD ["python3", "guardrail_server.py"]
