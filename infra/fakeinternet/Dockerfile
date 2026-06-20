FROM python:3.12-slim

# No extra packages needed — stdlib only.
RUN mkdir -p /logs

WORKDIR /app
COPY responder.py .

# Run as root so we can bind to privileged ports (53, 21, 25, 80, 443, 8080).
# This is our controlled infrastructure, not an untrusted package.
CMD ["python3", "-u", "responder.py"]
