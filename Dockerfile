# AppMap - container image for the web interface.
# Build:  docker build -t appmap .
# Run:    docker run -p 8000:8000 appmap
# Then open http://127.0.0.1:8000

FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    APPMAP_HOST=0.0.0.0 \
    APPMAP_PORT=8000

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Run behind gunicorn (a real WSGI server), not the Flask dev server.
EXPOSE 8000
CMD ["gunicorn", "-w", "2", "-b", "0.0.0.0:8000", "--timeout", "60", "dashboard:app"]
