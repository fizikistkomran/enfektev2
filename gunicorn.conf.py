# gunicorn.conf.py
import os

bind = f"0.0.0.0:{os.getenv('PORT', '8080')}"
workers = 1
threads = 8
timeout = 180
worker_class = "gthread"
loglevel = "debug"

# Reverse proxy ayarları
forwarded_allow_ips = "*"  # string, liste değil
secure_scheme_headers = {
    "X-FORWARDED-PROTOCOL": "ssl",
    "X-FORWARDED-PROTO": "https",
    "X-FORWARDED-SSL": "on",
}

