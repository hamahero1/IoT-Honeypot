FROM python:3.10-slim



WORKDIR /app

COPY app.py /app/app.py



RUN pip install --no-cache-dir flask



ENV LOG_PATH=/logs/http_honeypot.jsonl

EXPOSE 8080



CMD ["python", "/app/app.py"]
