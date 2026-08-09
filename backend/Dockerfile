FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

EXPOSE 8000

# The database file path must be overridden in composition when persistence
# is wanted (see docker-compose.yml -> CYBERSHIELD_DATABASE_URL).
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]