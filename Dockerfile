# SecureBridge OT Security Platform
# Multi-stage Dockerfile for production deployment
# Sandy Lukita | PT Optima Sarana Instrument

FROM python:3.11-slim AS base

# Metadata
LABEL maintainer="Sandy Lukita <sandylukita@gmail.com>"
LABEL description="SecureBridge AI-Powered OT Security Platform"
LABEL version="1.0.0"

# System dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    libpcap-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Working directory
WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create data directories
RUN mkdir -p data/logs data/models data/reports

# Non-root user for security
RUN useradd -m -u 1000 securebridge && \
    chown -R securebridge:securebridge /app
USER securebridge

# Default: dashboard mode
EXPOSE 8501

CMD ["streamlit", "run", "dashboard/app.py", \
     "--server.address=0.0.0.0", \
     "--server.port=8501", \
     "--server.headless=true"]
