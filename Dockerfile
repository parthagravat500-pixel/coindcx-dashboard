FROM python:3.12-slim
WORKDIR /app
RUN useradd --uid 10001 --create-home researcher && mkdir /data && chown researcher /data
COPY --chown=researcher:researcher . /app
USER researcher
ENV BIND=0.0.0.0 PORT=8080 DATA_DIR=/data PYTHONUNBUFFERED=1
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz',timeout=3)"
CMD ["python", "app.py"]
