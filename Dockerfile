FROM python:3.11-slim

RUN apt-get update && apt-get install -y fping systemctl cron

# Copy the application code
COPY ./app /app

# Install requirements
RUN pip install -r /app/requirements.txt

# Set the working directory
WORKDIR /app

# Start App and cron
CMD ["/bin/bash", "-c", "systemctl enable cron --now && gunicorn --access-logfile - wol:app"]