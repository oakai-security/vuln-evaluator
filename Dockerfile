# Multi-stage non-root container for vuln-evaluator
FROM python:3.12-slim-bookworm AS builder

WORKDIR /app
RUN pip install --no-cache-dir uv

COPY pyproject.toml README.md /app/
RUN uv venv /app/.venv
ENV PATH="/app/.venv/bin:$PATH"

COPY src /app/src
RUN uv pip install --no-cache-dir .

# Runtime stage
FROM python:3.12-slim-bookworm AS runtime

# Create dedicated non-root user (UID 1001) in group oakai (GID 2000)
RUN groupadd -g 2000 oakai && \
    useradd -u 1001 -g oakai -s /bin/false -m vuln-eval

WORKDIR /app
COPY --from=builder /app/.venv /app/.venv
ENV PATH="/app/.venv/bin:$PATH"
ENV PYTHONUNBUFFERED=1
ENV UDS_SOCKET_PATH="/run/oakai/eval.sock"

# Pre-create socket directory with permissions
RUN mkdir -p /run/oakai && chown -R vuln-eval:oakai /run/oakai && chmod 770 /run/oakai

USER vuln-eval:oakai
ENTRYPOINT ["vuln-evaluator"]
CMD ["serve"]
