FROM python:3.13-alpine
WORKDIR /app
COPY . /app
RUN pip install --no-cache-dir -r requirements.txt
CMD ["sh", "-c", "gunicorn --log-level warning -w 4 -b 0.0.0.0:5000 --timeout 120 secure_file_storage.main:app"]
