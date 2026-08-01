FROM python:3.12-slim

WORKDIR /app
COPY pyproject.toml uv.lock* ./
COPY src ./src
RUN pip install --no-cache-dir .

# Ensure the installed container also prefers the source copy for package data (UI assets)
ENV PYTHONPATH=/app/src

ARG TRIVY_VERSION=0.46.1

# Install minimal tools and download Trivy CLI
RUN apt-get update \
	&& apt-get install -y --no-install-recommends ca-certificates wget gnupg dirmngr bash git \
	&& wget -qO /tmp/trivy.tar.gz https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz \
	&& tar -xzf /tmp/trivy.tar.gz -C /tmp \
	&& bash -lc '\
		if [ -f /tmp/trivy ]; then mv /tmp/trivy /usr/local/bin/trivy; \
		elif [ -f /tmp/trivy_${TRIVY_VERSION} ]; then mv /tmp/trivy_${TRIVY_VERSION} /usr/local/bin/trivy; \
		else mv /tmp/*trivy* /usr/local/bin/trivy 2>/dev/null || true; fi' \
	&& chmod +x /usr/local/bin/trivy || true \
	&& rm -rf /var/lib/apt/lists/* /tmp/trivy*

# Run as a non-root user. /app/data holds the SQLite DB and cloned repositories;
# when docker-compose bind-mounts a host directory over it, host permissions apply instead.
RUN groupadd --gid 1000 appuser \
	&& useradd --uid 1000 --gid appuser --home-dir /app --shell /usr/sbin/nologin appuser \
	&& mkdir -p /app/data \
	&& chown -R appuser:appuser /app
USER appuser

EXPOSE 8000
CMD ["uvicorn", "security_review.main:app", "--host", "0.0.0.0", "--port", "8000"]
