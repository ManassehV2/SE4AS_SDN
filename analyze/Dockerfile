# Base image
FROM python:3.9-slim

# Set working directory
WORKDIR /app

# Copy application files
COPY app/ /app/

# Install required packages
RUN pip install flask requests pandas scikit-learn joblib

# Run the application
CMD ["python", "analyze.py"]
