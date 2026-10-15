FROM python:3.14-slim
WORKDIR /app
ENV PYTHONUNBUFFERED=1 OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY server.py service.py content_checks.py model_pipeline.py evaluation_results.json ./
COPY models ./models
COPY data/merchants.json ./data/merchants.json
COPY dist ./dist
RUN mkdir -p /data
ENV UPI_GUARD_DB_PATH=/data/events.db HOST=0.0.0.0 PORT=4173
CMD ["python", "server.py"]
