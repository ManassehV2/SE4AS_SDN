FROM python:3.9-slim

WORKDIR /app

# Copy application code
COPY app/ /app/

# Install required Python dependencies
RUN pip install flask requests influxdb-client

CMD ["python", "plan.py"]
