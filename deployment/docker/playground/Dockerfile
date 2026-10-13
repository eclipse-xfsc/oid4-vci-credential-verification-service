FROM python:3.12-alpine
WORKDIR /app
RUN pip install --no-cache-dir nats-py==2.10.0 aiohttp==3.11.18
COPY app.py /app/app.py
EXPOSE 8090
CMD ["python", "-u", "/app/app.py"]
