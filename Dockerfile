FROM python:3.13-alpine
WORKDIR /app
COPY . /app
RUN python secure_file_storage/src/setup_env.py
RUN pip install --no-cache-dir -r requirements.txt
CMD ["sh", "-c", "python secure_file_storage/src/setup_env.py && gunicorn --bind 0.0.0.0:5000 secure_file_storage.main:app"]
