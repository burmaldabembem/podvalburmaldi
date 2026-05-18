FROM python:3.11-slim

WORKDIR /app

# Системные зависимости для psycopg2
RUN apt-get update && apt-get install -y \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Копируем бэкенд
COPY main.txt ./main.py

# Статика (HTML-фронтенд)
RUN mkdir -p /app/static
COPY pelmeni_v2__2___1_.html /app/static/pelmeni_v2__2_.html

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
