# Dedicated test image: never copy a deployment database, credentials, or .git.
FROM python:3.12-slim
WORKDIR /app
COPY *.py index.html ui.js /app/
COPY ci/isolated_checks.py /app/ci/isolated_checks.py
USER 65532:65532
ENV DATA_DIR=/tmp/scopeguard-test-data PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
CMD ["python", "-m", "ci.isolated_checks"]
