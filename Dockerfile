FROM python:3.11.8-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    gcc \
    libmagic1 \
    libmagic-dev \
    && apt-get upgrade -y \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN useradd -m -u 1000 appuser && \
    chown -R appuser:appuser /app
USER appuser

ENV PYTHONUNBUFFERED=1
ENV DSHIELD_INTERVAL=300
ENV DSHIELD_UPDATE_EXISTING_DATA=true
ENV DSHIELD_CONFIDENCE_LEVEL=60
ENV DSHIELD_UPDATE_FREQUENCY=300

CMD ["python", "main.py"] 