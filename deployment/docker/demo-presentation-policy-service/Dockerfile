FROM python:3.13-alpine
WORKDIR /app
COPY server.py .
COPY policies/ ./policies/
USER 65534:65534
EXPOSE 8080
CMD ["python", "-u", "server.py"]
