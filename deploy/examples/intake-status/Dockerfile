FROM docker.io/library/python:3.15-slim@sha256:65a65fc7b30b06cb6df4930fd4650697cb23f4c2698ab81fc87e4b031bc36928

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /opt/intake-status
COPY intake_status.py .
USER 65532:65532
EXPOSE 8080
CMD ["python", "intake_status.py"]
