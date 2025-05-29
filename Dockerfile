FROM python:3.11.8-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    libmagic1 \
    libmagic-dev \
    && apt-get upgrade -y \
    && rm -rf /var/lib/apt/lists/*

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy connector code
COPY . .

# Set environment variables
ENV PYTHONUNBUFFERED=1

# Run the connector
CMD ["python", "main.py"] 