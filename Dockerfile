FROM python:3.11-slim
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends build-essential && rm -rf /var/lib/apt/lists/*
COPY pyproject.toml poetry.lock* /app/
RUN pip install poetry==1.8.5 && \
    poetry config virtualenvs.create false && \
    poetry install && \
    pip install python-multipart
COPY vault /app/vault
EXPOSE 8000
CMD ["uvicorn", "vault.gui_web:app", "--host", "0.0.0.0", "--port", "8000"]