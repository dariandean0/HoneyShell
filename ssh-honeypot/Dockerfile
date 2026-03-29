FROM python:3.11-slim
 
WORKDIR /app
 
RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*
 
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
 
COPY . .
 
RUN mkdir -p /app/logs
 
EXPOSE 2222
 
CMD ["python", "server.py"]
