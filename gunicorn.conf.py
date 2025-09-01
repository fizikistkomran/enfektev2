# gunicorn.conf.py
import os

# Railway'in verdiği PORT'u oku; yoksa 8080
bind = f"0.0.0.0:{os.getenv('PORT', '8080')}"
workers = 1
threads = 8
timeout = 180
worker_class = "gthread"
loglevel = "debug"

# proxy header'ları (Railway için güvenli)
forwarded_allow_ips = ["*"]
secure_scheme_headers = {
    "X-FORWARDED-PROTOCOL": "ssl",
    "X-FORWARDED-PROTO": "https",
    "X-FORWARDED-SSL": "on",
}

