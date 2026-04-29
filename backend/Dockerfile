FROM python:3.12-slim
WORKDIR /app
COPY backend/ /app/
RUN pip install --no-cache-dir fastapi uvicorn watchdog psutil
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "5000"]
