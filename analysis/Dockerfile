FROM python:3.12-slim

WORKDIR /app

# Install dependencies
RUN pip install --no-cache-dir flask flask-cors requests pyyaml gunicorn

# Copy analysis module
COPY *.py ./
COPY config.yaml ./

# Create non-root user
RUN useradd -m -r sib && chown -R sib:sib /app
USER sib

EXPOSE 5000

# Use gunicorn for production
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--timeout", "120", "api:app"]
