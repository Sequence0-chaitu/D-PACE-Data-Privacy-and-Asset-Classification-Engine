FROM python:3.12-slim

LABEL maintainer="D-PACE Project"
LABEL description="D-PACE — Data Privacy & Asset Classification Engine"

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY dpace/ ./dpace/
COPY rules/ ./rules/

# Create directories
RUN mkdir -p /app/reports /app/dpace/db

# Non-root user for security
RUN useradd -m dpace && chown -R dpace:dpace /app
USER dpace

ENTRYPOINT ["python", "-m", "dpace.cli"]
CMD ["--help"]
