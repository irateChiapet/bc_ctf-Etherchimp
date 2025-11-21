# Use Python 3.11 slim image
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies for packet capture and network tools
RUN apt-get update && apt-get install -y \
    tcpdump \
    libpcap-dev \
    gcc \
    g++ \
    openssh-client \
    sshpass \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements file
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY app.py .
COPY backend/ ./backend/
COPY static/ ./static/
COPY templates/ ./templates/

# Create uploads directory
RUN mkdir -p uploads

# Expose the default port
EXPOSE 5001

# Set environment variables
ENV PYTHONUNBUFFERED=1

# Run the application
CMD ["python", "app.py", "-p", "5001"]
