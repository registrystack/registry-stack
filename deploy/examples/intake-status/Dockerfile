FROM docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /opt/intake-status
COPY intake_status.py .
USER 65532:65532
EXPOSE 8080
CMD ["python", "intake_status.py"]
