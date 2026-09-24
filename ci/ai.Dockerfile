# Official pinned llama.cpp release is SHA-256 checked before this build.
# Build context contains these scripts and the binary archive only, never a model,
# checkout, deployment credentials or the runner's ephemeral OIDC environment.
FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends python3 libgomp1 libcurl4t64 ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY llama.tar.gz /tmp/llama.tar.gz
RUN mkdir /opt/llama && tar -xzf /tmp/llama.tar.gz -C /opt/llama && rm /tmp/llama.tar.gz
COPY ai_review.py isolated_checks.py /app/ci/
USER 65532:65532
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
CMD ["python3", "-m", "ci.ai_review"]
