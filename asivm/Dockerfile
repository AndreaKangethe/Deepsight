FROM python:3.12-slim

ARG INSTALL_TRIVY=true
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends nmap curl ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && if [ "$INSTALL_TRIVY" = "true" ]; then \
         (curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin) \
         || echo "WARNING: Trivy install failed; Trivy report import still works"; \
       fi

WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
COPY static ./static

RUN useradd -r -m -u 10001 asivm && mkdir -p /data/models && chown asivm /data/models
ENV ASIVM_MODEL_DIR=/data/models
USER asivm
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s \
  CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8000/health')" || exit 1
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
