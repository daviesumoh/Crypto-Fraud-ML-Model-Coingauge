FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml README.md ./
COPY sentinel_ml ./sentinel_ml
COPY data/malicious_bytecodes.json ./data/malicious_bytecodes.json
RUN pip install --no-cache-dir .
EXPOSE 8091
CMD ["uvicorn", "sentinel_ml.server:app", "--host", "0.0.0.0", "--port", "8091"]

