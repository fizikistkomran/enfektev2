FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Bağımlılıkları kur
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Uygulamayı kopyala
COPY . .

# Railway $PORT verir; yoksa local için 8080
ENV PORT=${PORT:-8080}

# Sağlıklı başlatma: $PORT'a bind et
CMD bash -lc "gunicorn app:app --bind 0.0.0.0:${PORT} --workers 1 --threads 8 --timeout 180 --log-level debug"

