FROM python:3.12-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY main.py .

# Create non-root user with explicit UID for Kubernetes runAsNonRoot
RUN useradd --create-home --shell /bin/bash --uid 1000 appuser
USER 1000

ENV PORT=8000
EXPOSE 8000

CMD ["python", "main.py"]

