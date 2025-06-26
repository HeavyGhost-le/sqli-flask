# Use official Python slim image
FROM python:3.11-slim

# Set working directory in container
WORKDIR /app

# Copy the application code to the container
COPY app/ /app/

# Install Flask
RUN pip install --no-cache-dir flask

# Expose port 5000 for Flask
EXPOSE 5000

# Command to run your Flask app
CMD ["python", "app.py"]
