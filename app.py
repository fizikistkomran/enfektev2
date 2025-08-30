import os, smtplib, ssl, json, time, traceback, secrets, io, csv
from email.message import EmailMessage
from urllib.parse import urlencode, quote
import requests
import certifi
import qrcode

from flask import Flask, render_template, redirect, url_for, session, request, flash, send_file, abort, Response
from dotenv import load_dotenv
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from sqlalchemy import create_engine, text

# --- .env ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DOTENV_PATH = os.path.join(BASE_DIR, ".env")
load_dotenv(DOTENV_PATH)

DEBUG_TRACE   = os.getenv("DEBUG_TRACE", "0") == "1"
VERIFY_SSL    = os.getenv("VERIFY_SSL", "true").lower() == "true"
REQUESTS_VERIFY = (certifi.where() if VERIFY_SSL else False)

def now_ts(): return float(time.time())
def ts2human(ts):
    if not ts: return "-"
    try:
        return time.strftime("%Y-%m-%d %H:%M", time.localtime(float(ts)))
    except Exception:
        return "-"

def slugify(name: str) -> str:
    s = "".join(ch.lower() if ch.isalnum() else "-" for ch in name.strip())
    s = "-".join([p for p in s.split("-") if p])
    s = s[:40]
    return s + "-" + secrets.token_hex(2)

def create_app():
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-secret-key")
    app.config["HOST_URL"]   = os.getenv("HOST_URL", "http://localhost:8000")
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["SESSION_COOKIE_SECURE"]   = False  # localhost

    # --- DB ---
    DB_URL = os.getenv("DATABASE_URL", "sqlite:///enfekte.db")
    engine = create_engine(DB_URL, echo=False, future=True)
    with engine.begin() as con:
        con.exec_driver_sql("""
        CREATE TABLE IF NOT EXISTS users(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          linkedin_id TEXT UNIQUE,
          name TEXT,
          avatar_url TEXT,
          edu_email TEXT,
          edu_verified_at REAL,
          created_at REAL DEFAULT (strftime('%s','now'))
        );""")
        con.exec_driver_sql("""
        CREATE TABLE IF NOT EXISTS clubs(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          name TEXT NOT NULL,
          slug TEXT UNIQUE,
          owner_user_id INTEGER NOT NULL,
          created_at REAL DEFAULT (strftime('%s','now'))
        );""")
        con.exec_driver_sql("""
        CREATE TABLE IF NOT EXISTS club_members(
          club_id INTEGER NOT NULL,
          user_id INTEGER NOT NULL,
          role TEXT NOT NULL DEFAULT 'member',
          joined_at REAL DEFAULT (strftime('%s','now')),
          PRIMARY KEY (club_id, user_id)
        );""")
        con.exec_driver_sql("""
        CREATE TABLE IF NOT EXISTS events(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          club_id INTEGER NOT NULL,
          title TEXT NOT NULL,
          starts_at REAL,
          ends_at REAL,
          qr_secret TEXT NOT NULL,
          created_by INTEGER NOT NULL,
          created_at REAL DEFAULT (strftime('%s','now'))
        );""")
        con.exec_driver_sql("""
        CREATE TABLE IF NOT EXISTS checkins(
          event_id INTEGER NOT NULL,
          user_id INTEGER NOT NULL,
          checked_at REAL DEFAULT (strftime('%s','now')),
          via_qr_secret TEXT,
          PRIMARY KEY (event_id, user_id)
        );""")
        con.exec_driver_sql("""
        CREATE TABLE IF NOT EXISTS graph_edges(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          club_id INTEGER NOT NULL,
          src_user_id INTEGER NOT NULL,
          dst_user_id INTEGER NOT NULL,
          status TEXT NOT NULL DEFAULT 'pending',
          created_at REAL DEFAULT (strftime('%s','now')),
          UNIQUE (club_id, src_user_id, dst_user_id)
        );""")

    serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"])

    # ---------- Helpers ----------
    def current_user():
        uid = session.get("uid")
        if not uid: return None
        with engine.begin() as con:
            row = con.execute(text("SELECT * FROM users WHERE id=:id"), {"id": uid}).mappings().first()
            return dict(row) if row else None

    def allowed_edu(email: str) -> bool:
        if not email: return False
        allowed = os.getenv("EDU_ALLOWED_DOMAINS", "")
        domains = [d.strip().lower() for d in allowed.split(",") if d.strip()]
        return any(email.lower().endswith("@" + d) for d in domains)

    def ensure_member(club_id: int, user_id: int, role_default="member"):
        with engine.begin() as con:
            row = con.execute(text("""
              SELECT role FROM club_members WHERE club_id=:c AND user_id=:u
            """), {"c": club_id, "u": user_id}).first()
            if not row:
                con.execute(text("""
                  INSERT INTO club_members (club_id, user_id, role, joined_at)
                  VALUES (:c,:u,:r,:t)
                """), {"c": club_id, "u": user_id, "r": role_default, "t": now_ts()})

    def is_admin_or_owner(club_id: int, user_id: int) -> bool:
        with engine.begin() as con:
            row = con.execute(text("""
              SELECT role FROM club_members WHERE club_id=:c AND user_id=:u
            """), {"c": club_id, "u": user_id}).first()
            if row and row[0] in ("owner","admin"): return True
            club = con.execute(text("SELECT owner_user_id FROM clubs WHERE id=:c"), {"c": club_id}).first()
            return bool(club and club[0] == user_id)

    def send_mail(to_email: str, subject: str, html: str, text_body: str = None):
        host = os.getenv("SMTP_HOST") or ""
        user = os.getenv("SMTP_USER") or ""
        pwd  = os.getenv("SMTP_PASS") or ""
        port = int(os.getenv("SMTP_PORT", "587"))
        from_addr = os.getenv("SMTP_FROM", "enfekte.co <no-reply@enfekte.co>")
        use_tls = (os.getenv("SMTP_USE_TLS","true").lower() == "true")

        if not host or not user or not pwd:
            print("\n[DEV] SMTP boş: doğrulama e-postası gönderilmiyor.")
            print("[DEV] TO:", to_email)
            print("[DEV] SUBJECT:", subject)
            print("[DEV] BODY:\n", html, "\n")
            return

        msg = EmailMessage()
        msg["From"] = from_addr
        msg["To"] = to_email
        msg["Subject"] = subject
        msg.set_content(text_body or "Please verify your email.")
        msg.add_alternative(html, subtype="html")

        ctx = ssl.create_default_context()
        with smtplib.SMTP(host, port) as smtp:
            if use_tls:
                smtp.starttls(context=ctx)
            smtp.login(user, pwd)
            smtp.send_message(msg)

    # Jinja helpers
    app.jinja_env.filters["ts"] = ts2human

    # ---------- ROUTES ----------
    @app.get("/health")
    def health(): return {"ok": True}

    @app.get("/")
    def index():
        return render_template("index.html", user=current_user())

    @app.get("/dashboard")
    def dashboard():
        user = current_user()
        if not user: return redirect(url_for("index"))
        with engine.begin() as con:
            clubs = con.execute(text("""
              SELECT c.*, 
                     (SELECT COUNT(*) FROM club_members m WHERE m.club_id=c.id) AS member_count,
                     (SELECT COUNT(*) FROM events e WHERE e.club_id=c.id) AS event_count
              FROM clubs c
              JOIN club_members m ON m.club_id=c.id AND m.user_id=:u
              ORDER BY c.created_at DESC
            """), {"u": user["id"]}).mappings().all()
        return render_template("dashboard.html", user=user, clubs=clubs)

    @app.get("/logout")
    def logout():
        session.clear()
        return redirect(url_for("index"))

    # ---------- LinkedIn OAuth2 (manual flow) ----------
    @app.get("/auth/linkedin/login")
    def li_login():
        nxt = request.args.get("next")
        if nxt: session["next_url"] = nxt
        client_id = os.getenv("LINKEDIN_CLIENT_ID")
        redirect_uri = app.config["HOST_URL"].rstrip("/") + url_for("li_callback")
        state = secrets.token_urlsafe(16)
        nonce = secrets.token_urlsafe(16)
        session["oauth_state"] = state
        session["oidc_nonce"] = nonce
        params = {
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": "openid profile email",
            "state": state,
            "nonce": nonce,
        }
        auth_url = "https://www.linkedin.com/oauth/v2/authorization?" + urlencode(params)
        if DEBUG_TRACE:
            print("[DEBUG] authorize_redirect to:", redirect_uri, "| nonce:", nonce)
        return redirect(auth_url)

    @app.get("/auth/linkedin/callback")
    def li_callback():
        if request.args.get("error"):
            flash(f"LinkedIn yetkilendirme hatası: {request.args.get('error_description','error')}", "danger")
            return redirect(url_for("index"))

        state = request.args.get("state")
        if not state or state != session.get("oauth_state"):
            flash("CSRF uyarısı: state uyuşmuyor.", "danger")
            return redirect(url_for("index"))

        code = request.args.get("code")
        if not code:
            flash("Yetkilendirme kodu alınamadı.", "danger")
            return redirect(url_for("index"))

        token_url = "https://www.linkedin.com/oauth/v2/accessToken"
        redirect_uri = app.config["HOST_URL"].rstrip("/") + url_for("li_callback")
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": os.getenv("LINKEDIN_CLIENT_ID"),
            "client_secret": os.getenv("LINKEDIN_CLIENT_SECRET"),
        }
        try:
            resp = requests.post(
                token_url, data=data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=20, verify=REQUESTS_VERIFY
            )
            if DEBUG_TRACE:
                print("[DEBUG] accessToken status:", resp.status_code, "| body:", resp.text[:500])
            if resp.status_code != 200:
                flash("LinkedIn access token alınamadı.", "danger")
                return redirect(url_for("index"))
            tok = resp.json()
            access_token = tok.get("access_token")
            if not access_token:
                flash("Access token bulunamadı.", "danger")
                return redirect(url_for("index"))
        except Exception:
            print("[ERROR] Token exchange failed:"); traceback.print_exc()
            flash("Token değişiminde hata oluştu.", "danger")
            return redirect(url_for("index"))

        headers = {"Authorization": f"Bearer {access_token}", "X-Restli-Protocol-Version": "2.0.0"}

        sub = name = email = avatar = None
        # userinfo (OIDC)
        try:
            uresp = requests.get("https://api.linkedin.com/v2/userinfo", headers=headers, timeout=15, verify=REQUESTS_VERIFY)
            if DEBUG_TRACE: print("[DEBUG] userinfo status:", uresp.status_code, "| body:", uresp.text[:300])
            if uresp.status_code == 200:
                uj = uresp.json()
                sub = uj.get("sub")
                name = uj.get("name") or (uj.get("given_name","") + " " + uj.get("family_name","")).strip() or "LinkedIn User"
                email = uj.get("email") or uj.get("emailAddress")
                avatar = uj.get("picture")
        except Exception:
            if DEBUG_TRACE: traceback.print_exc()

        # Fallback v2 endpoints
        try:
            if not sub:
                me = requests.get(
                    "https://api.linkedin.com/v2/me?projection=(id,localizedFirstName,localizedLastName,profilePicture(displayImage~:playableStreams))",
                    headers=headers, timeout=15, verify=REQUESTS_VERIFY
                )
                if me.status_code == 200:
                    mp = me.json()
                    sub = mp.get("id")
                    first = mp.get("localizedFirstName","")
                    last  = mp.get("localizedLastName","")
                    name = (first + " " + last).strip() or name or "LinkedIn User"
                    try:
                        pics = mp["profilePicture"]["displayImage~"]["elements"]
                        if pics: avatar = pics[-1]["identifiers"][0]["identifier"]
                    except Exception: pass
            if not email:
                mail = requests.get(
                    "https://api.linkedin.com/v2/emailAddress?q=members&projection=(elements*(handle~))",
                    headers=headers, timeout=15, verify=REQUESTS_VERIFY
                )
                if mail.status_code == 200:
                    mj = mail.json()
                    try: email = mj["elements"][0]["handle~"]["emailAddress"]
                    except Exception: pass
        except Exception:
            print("[ERROR] Fallback v2 endpoints failed:"); traceback.print_exc()

        if not sub:
            flash("LinkedIn kullanıcı bilgisi alınamadı. Lütfen tekrar deneyin.", "danger")
            return redirect(url_for("index"))

        # upsert
        with engine.begin() as con:
            row = con.execute(text("SELECT id FROM users WHERE linkedin_id=:lid"), {"lid": sub}).first()
            if row:
                uid = row[0]
                con.execute(text("UPDATE users SET name=:n, avatar_url=:a WHERE id=:id"),
                            {"n": name, "a": avatar, "id": uid})
            else:
                res = con.execute(text(
                    "INSERT INTO users (linkedin_id, name, avatar_url, edu_email) VALUES (:lid,:n,:a,:e)"
                ), {"lid": sub, "n": name, "a": avatar, "e": email})
                uid = res.lastrowid

        session["uid"] = uid
        flash("Giriş başarılı.", "success")

        nxt = session.get("next_url")
        if email and allowed_edu(email):
            return redirect(url_for("verify", next=nxt) if nxt else url_for("verify"))
        return redirect(nxt or url_for("dashboard"))

    # ---------- EDU doğrulama ----------
    @app.get("/verify")
    def verify():
        user = current_user()
        if not user: return redirect(url_for("index"))
        nxt = request.args.get("next")
        if nxt: session["next_url"] = nxt
        return render_template("verify.html", user=user,
                               allowed=os.getenv("EDU_ALLOWED_DOMAINS","itu.edu.tr"))

    @app.post("/verify/start")
    def verify_start():
        user = current_user()
        if not user: return redirect(url_for("index"))
        edu_email = (request.form.get("edu_email") or "").strip()
        if not edu_email:
            flash("E-posta gerekli.", "danger")
            return redirect(url_for("verify"))
        if not allowed_edu(edu_email):
            flash("Bu alan izinli değil. İzinli alanlar: " + os.getenv("EDU_ALLOWED_DOMAINS",""), "danger")
            return redirect(url_for("verify"))
        token = serializer.dumps({"uid": user["id"], "email": edu_email})
        link = app.config["HOST_URL"].rstrip("/") + url_for("verify_confirm") + "?" + urlencode({"token": token})
        html = f"""
        <p>Merhaba {user['name']},</p>
        <p>EDU e-posta doğrulaması için bağlantı:</p>
        <p><a href="{link}">E-posta doğrula</a></p>
        <p>Bağlantı 30 dk geçerlidir.</p>
        """
        send_mail(edu_email, "enfekte.co · EDU e-posta doğrulaması", html, "EDU doğrulama linkiniz: " + link)
        flash("Doğrulama bağlantısı gönderildi. (SMTP yoksa link terminale yazdırıldı.)", "info")
        return redirect(url_for("verify"))

    @app.get("/verify/confirm")
    def verify_confirm():
        token = request.args.get("token","")
        if not token:
            flash("Token eksik.", "danger")
            return redirect(url_for("verify"))
        try:
            data = serializer.loads(token, max_age=1800)
        except SignatureExpired:
            flash("Token süresi doldu.", "danger")
            return redirect(url_for("verify"))
        except BadSignature:
            flash("Token geçersiz.", "danger")
            return redirect(url_for("verify"))

        uid = data.get("uid"); email = data.get("email")
        with engine.begin() as con:
            con.execute(text("UPDATE users SET edu_email=:e, edu_verified_at=:t WHERE id=:id"),
                        {"e": email, "t": now_ts(), "id": uid})
        flash("EDU e-posta doğrulandı.", "success")
        session["uid"] = uid
        nxt = session.pop("next_url", None)
        return redirect(nxt or url_for("dashboard"))

    # ---------- Kulüp ----------
    @app.get("/clubs/new")
    def club_new():
        user = current_user()
        if not user: return redirect(url_for("li_login", next=request.url))
        return render_template("club_new.html", user=user)

    @app.post("/clubs/new")
    def club_new_post():
        user = current_user()
        if not user: return redirect(url_for("li_login", next=request.url))
        name = (request.form.get("name") or "").strip()
        if not name:
            flash("Kulüp adı zorunlu.", "danger")
            return redirect(url_for("club_new"))
        s = slugify(name)
        with engine.begin() as con:
            res = con.execute(text("""
              INSERT INTO clubs (name, slug, owner_user_id, created_at)
              VALUES (:n,:s,:o,:t)
            """), {"n": name, "s": s, "o": user["id"], "t": now_ts()})
            club_id = res.lastrowid
            con.execute(text("""
              INSERT OR REPLACE INTO club_members(club_id, user_id, role, joined_at)
              VALUES (:c,:u,'owner',:t)
            """), {"c": club_id, "u": user["id"], "t": now_ts()})
        flash("Kulüp oluşturuldu.", "success")
        return redirect(url_for("club_detail", club_id=club_id))

    @app.get("/clubs/<int:club_id>")
    def club_detail(club_id):
        user = current_user()
        if not user: return redirect(url_for("li_login", next=request.url))
        with engine.begin() as con:
            club = con.execute(text("SELECT * FROM clubs WHERE id=:c"), {"c": club_id}).mappings().first()
            if not club: abort(404)
            ensure_member(club_id, user["id"])
            events = con.execute(text("""
               SELECT e.*, 
                      (SELECT COUNT(*) FROM checkins ci WHERE ci.event_id=e.id) AS checkin_count
               FROM events e WHERE e.club_id=:c ORDER BY e.created_at DESC
            """), {"c": club_id}).mappings().all()

            # Üyeler + mevcut ilişki durumu (me ile)
            members = con.execute(text("""
               SELECT 
                 u.id, u.name, u.avatar_url, m.role,
                 (
                   SELECT ge.status 
                   FROM graph_edges ge 
                   WHERE ge.club_id=:c 
                     AND ((ge.src_user_id=:me AND ge.dst_user_id=u.id) OR (ge.src_user_id=u.id AND ge.dst_user_id=:me))
                   LIMIT 1
                 ) AS relation_status,
                 (
                   SELECT CASE WHEN ge.src_user_id=:me AND ge.status='pending' THEN 1 ELSE 0 END
                   FROM graph_edges ge 
                   WHERE ge.club_id=:c AND ge.src_user_id=:me AND ge.dst_user_id=u.id
                   LIMIT 1
                 ) AS i_sent_pending,
                 (
                   SELECT CASE WHEN ge.src_user_id=u.id AND ge.dst_user_id=:me AND ge.status='pending' THEN 1 ELSE 0 END
                   FROM graph_edges ge 
                   WHERE ge.club_id=:c AND ge.src_user_id=u.id AND ge.dst_user_id=:me
                   LIMIT 1
                 ) AS they_sent_pending
               FROM club_members m 
               JOIN users u ON u.id=m.user_id
               WHERE m.club_id=:c
               ORDER BY CASE WHEN u.id=:me THEN 0 ELSE 1 END, u.name
            """), {"c": club_id, "me": user["id"]}).mappings().all()

            incoming = con.execute(text("""
               SELECT ge.*, u.name, u.avatar_url
               FROM graph_edges ge 
               JOIN users u ON u.id=ge.src_user_id
               WHERE ge.club_id=:c AND ge.dst_user_id=:me AND ge.status='pending'
            """), {"c": club_id, "me": user["id"]}).mappings().all()
        owner = is_admin_or_owner(club_id, user["id"])
        return render_template("club_dashboard.html", user=user, club=club, events=events, members=members,
                               incoming=incoming, owner=owner)

    # ---------- Etkinlik + QR ----------
    @app.get("/clubs/<int:club_id>/events/new")
    def event_new(club_id):
        user = current_user()
        if not user: return redirect(url_for("li_login", next=request.url))
        if not is_admin_or_owner(club_id, user["id"]):
            flash("Bu kulüpte etkinlik oluşturma yetkin yok.", "danger")
            return redirect(url_for("club_detail", club_id=club_id))
        return render_template("event_create.html", user=user, club_id=club_id)

    @app.post("/clubs/<int:club_id>/events/new")
    def event_new_post(club_id):
        user = current_user()
        if not user: return redirect(url_for("li_login", next=request.url))
        if not is_admin_or_owner(club_id, user["id"]):
            flash("Bu kulüpte etkinlik oluşturma yetkin yok.", "danger")
            return redirect(url_for("club_detail", club_id=club_id))
        title = (request.form.get("title") or "").strip()
        starts = (request.form.get("starts_at") or "").strip()
        ends   = (request.form.get("ends_at") or "").strip()
        if not title:
            flash("Başlık gerekli.", "danger")
            return redirect(url_for("event_new", club_id=club_id))
        def parse_dt(s):
            if not s: return None
            try:
                import datetime as dt
                return time.mktime(dt.datetime.strptime(s, "%Y-%m-%dT%H:%M").timetuple())
            except Exception:
                return None
        starts_at = parse_dt(starts); ends_at = parse_dt(ends)
        qr_secret = secrets.token_urlsafe(16)
        with engine.begin() as con:
            res = con.execute(text("""
              INSERT INTO events (club_id, title, starts_at, ends_at, qr_secret, created_by, created_at)
              VALUES (:c,:t,:s,:e,:q,:u,:now)
            """), {"c": club_id, "t": title, "s": starts_at, "e": ends_at, "q": qr_secret, "u": user["id"], "now": now_ts()})
            event_id = res.lastrowid
        flash("Etkinlik oluşturuldu.", "success")
        return redirect(url_for("event_live", event_id=event_id))

    @app.get("/events/<int:event_id>/live")
    def event_live(event_id):
        user = current_user()
        if not user: return redirect(url_for("li_login", next=request.url))
        with engine.begin() as con:
            ev = con.execute(text("SELECT * FROM events WHERE id=:id"), {"id": event_id}).mappings().first()
            if not ev: abort(404)
            club = con.execute(text("SELECT * FROM clubs WHERE id=:c"), {"c": ev["club_id"]}).mappings().first()
            if not club: abort(404)
            if not is_admin_or_owner(ev["club_id"], user["id"]):
                flash("Bu etkinliğin canlı ekranına erişimin yok.", "danger")
                return redirect(url_for("club_detail", club_id=ev["club_id"]))
            cnt = con.execute(text("SELECT COUNT(*) FROM checkins WHERE event_id=:e"), {"e": event_id}).scalar() or 0
        join_url = app.config["HOST_URL"].rstrip("/") + url_for("join") + f"?e={event_id}&q={quote(ev['qr_secret'])}"
        return render_template("event_live_qr.html", user=user, event=ev, club=club, join_url=join_url, count=cnt)

    @app.get("/events/<int:event_id>/qr.png")
    def event_qr_png(event_id):
        with engine.begin() as con:
            ev = con.execute(text("SELECT id, qr_secret FROM events WHERE id=:id"), {"id": event_id}).mappings().first()
            if not ev: abort(404)
        join_url = app.config["HOST_URL"].rstrip("/") + url_for("join") + f"?e={event_id}&q={quote(ev['qr_secret'])}"
        img = qrcode.make(join_url)
        buf = io.BytesIO(); img.save(buf, format="PNG"); buf.seek(0)
        return send_file(buf, mimetype="image/png", max_age=0)

    # ---------- QR ile check-in ----------
    @app.get("/join")
    def join():
        e = request.args.get("e", type=int)
        q = request.args.get("q", type=str)
        if not e or not q:
            flash("Etkinlik bilgisi eksik.", "danger")
            return redirect(url_for("index"))
        user = current_user()
        if not user:
            session["next_url"] = request.url
            return redirect(url_for("li_login"))
        with engine.begin() as con:
            ev = con.execute(text("SELECT * FROM events WHERE id=:id"), {"id": e}).mappings().first()
            if not ev:
                flash("Etkinlik bulunamadı.", "danger")
                return redirect(url_for("index"))
            if ev["qr_secret"] != q:
                flash("Geçersiz QR.", "danger")
                return redirect(url_for("index"))
            ensure_member(ev["club_id"], user["id"])
            con.execute(text("""
              INSERT OR IGNORE INTO checkins(event_id, user_id, checked_at, via_qr_secret)
              VALUES (:e,:u,:t,:q)
            """), {"e": e, "u": user["id"], "t": now_ts(), "q": q})
        flash("Yoklamaya eklendin. Hoş geldin! 👋", "success")
        return redirect(url_for("club_detail", club_id=ev["club_id"]))

    # ---------- Ağ: bağlantı istekleri ----------
    @app.post("/clubs/<int:club_id>/connect/<int:target_id>")
    def connect_send(club_id, target_id):
        user = current_user()
        if not user: return redirect(url_for("li_login", next=request.referrer or url_for("club_detail", club_id=club_id)))
        if user["id"] == target_id:
            flash("Kendine bağ isteği gönderemezsin.", "warning")
            return redirect(url_for("club_detail", club_id=club_id))
        ensure_member(club_id, user["id"]); ensure_member(club_id, target_id)
        with engine.begin() as con:
            ex = con.execute(text("""
              SELECT status, src_user_id, dst_user_id FROM graph_edges 
              WHERE club_id=:c AND 
                    ((src_user_id=:a AND dst_user_id=:b) OR (src_user_id=:b AND dst_user_id=:a))
            """), {"c": club_id, "a": user["id"], "b": target_id}).mappings().first()
            if ex:
                if ex["status"] == "accepted":
                    flash("Zaten bağlısınız.", "info")
                elif ex["status"] == "pending":
                    if ex["src_user_id"] == user["id"]:
                        flash("Zaten bekleyen isteğin var.", "info")
                    else:
                        flash("Karşı taraftan bekleyen istek var, kabul edebilirsin.", "info")
            else:
                con.execute(text("""
                  INSERT INTO graph_edges (club_id, src_user_id, dst_user_id, status, created_at)
                  VALUES (:c,:a,:b,'pending',:t)
                """), {"c": club_id, "a": user["id"], "b": target_id, "t": now_ts()})
                flash("Bağ isteği gönderildi.", "success")
        return redirect(url_for("club_detail", club_id=club_id))

    @app.post("/clubs/<int:club_id>/connect/accept")
    def connect_accept(club_id):
        user = current_user()
        if not user: return redirect(url_for("li_login", next=request.referrer or url_for("club_detail", club_id=club_id)))
        src_id = request.form.get("from_id", type=int)
        if not src_id:
            flash("Geçersiz istek.", "danger")
            return redirect(url_for("club_detail", club_id=club_id))
        with engine.begin() as con:
            res = con.execute(text("""
              UPDATE graph_edges SET status='accepted'
              WHERE club_id=:c AND src_user_id=:s AND dst_user_id=:me AND status='pending'
            """), {"c": club_id, "s": src_id, "me": user["id"]})
            if res.rowcount:
                flash("Bağ kabul edildi. 🎉", "success")
            else:
                flash("İstek bulunamadı veya durum değişmiş.", "warning")
        return redirect(url_for("club_detail", club_id=club_id))

    @app.post("/clubs/<int:club_id>/connect/reject")
    def connect_reject(club_id):
        user = current_user()
        if not user: return redirect(url_for("li_login", next=request.referrer or url_for("club_detail", club_id=club_id)))
        src_id = request.form.get("from_id", type=int)
        if not src_id:
            flash("Geçersiz istek.", "danger")
            return redirect(url_for("club_detail", club_id=club_id))
        with engine.begin() as con:
            res = con.execute(text("""
              UPDATE graph_edges SET status='rejected'
              WHERE club_id=:c AND src_user_id=:s AND dst_user_id=:me AND status='pending'
            """), {"c": club_id, "s": src_id, "me": user["id"]})
            if res.rowcount:
                flash("İstek reddedildi.", "info")
            else:
                flash("İstek bulunamadı.", "warning")
        return redirect(url_for("club_detail", club_id=club_id))

    @app.post("/clubs/<int:club_id>/connect/cancel")
    def connect_cancel(club_id):
        """Kullanıcının kendi gönderdiği bekleyen isteği iptal etmesi."""
        user = current_user()
        if not user: return redirect(url_for("li_login", next=request.referrer or url_for("club_detail", club_id=club_id)))
        target_id = request.form.get("to_id", type=int)
        if not target_id:
            flash("Geçersiz hedef.", "danger")
            return redirect(url_for("club_detail", club_id=club_id))
        with engine.begin() as con:
            res = con.execute(text("""
              DELETE FROM graph_edges 
              WHERE club_id=:c AND src_user_id=:me AND dst_user_id=:t AND status='pending'
            """), {"c": club_id, "me": user["id"], "t": target_id})
            if res.rowcount:
                flash("İstek iptal edildi.", "info")
            else:
                flash("İptal edilecek bekleyen istek bulunamadı.", "warning")
        return redirect(url_for("club_detail", club_id=club_id))

    # ---------- Ağ: görselleştirme ----------
    @app.get("/clubs/<int:club_id>/graph")
    def community_graph(club_id):
        user = current_user()
        if not user:
            return redirect(url_for("li_login", next=request.url))
        with engine.begin() as con:
            mem = con.execute(
                text("SELECT 1 FROM club_members WHERE club_id=:c AND user_id=:u"),
                {"c": club_id, "u": user["id"]}
            ).first()
            if not mem:
                flash("Bu kulübün ağına erişimin yok.", "danger")
                return redirect(url_for("dashboard"))
        return render_template("community_graph.html", user=user, club_id=club_id)

    @app.get("/clubs/<int:club_id>/graph.json")
    def club_graph_json(club_id):
        user = current_user()
        if not user: return {"error": "auth"}, 401
        with engine.begin() as con:
            mem = con.execute(text("""
              SELECT 1 FROM club_members WHERE club_id=:c AND user_id=:u
            """), {"c": club_id, "u": user["id"]}).first()
            if not mem:
                return {"error": "forbidden"}, 403
            nodes_rows = con.execute(text("""
              SELECT u.id AS id, u.name AS label, u.avatar_url AS avatar
              FROM club_members m JOIN users u ON u.id=m.user_id
              WHERE m.club_id=:c
            """), {"c": club_id}).mappings().all()
            edges_rows = con.execute(text("""
              SELECT src_user_id AS source, dst_user_id AS target
              FROM graph_edges 
              WHERE club_id=:c AND status='accepted'
            """), {"c": club_id}).mappings().all()
        nodes = [dict(r) for r in nodes_rows]
        edges = [dict(r) for r in edges_rows]
        if DEBUG_TRACE:
            print(f"[DEBUG] graph json club={club_id} nodes={len(nodes)} edges={len(edges)}")
        return {"nodes": nodes, "edges": edges}

    # ===================== ANALİTİKLER =====================

    @app.get("/events/<int:event_id>/analytics")
    def event_analytics(event_id):
        user = current_user()
        if not user: return redirect(url_for("li_login", next=request.url))

        with engine.begin() as con:
            ev = con.execute(text("SELECT * FROM events WHERE id=:id"), {"id": event_id}).mappings().first()
            if not ev: abort(404)
            club = con.execute(text("SELECT * FROM clubs WHERE id=:c"), {"c": ev["club_id"]}).mappings().first()
            if not club: abort(404)
            if not is_admin_or_owner(ev["club_id"], user["id"]):
                flash("Bu etkinliğin analitiğine erişimin yok.", "danger")
                return redirect(url_for("club_detail", club_id=ev["club_id"]))

            attendees = con.execute(text("""
              SELECT u.id, u.name, u.avatar_url, u.edu_email, ci.checked_at
              FROM checkins ci JOIN users u ON u.id=ci.user_id
              WHERE ci.event_id=:e
              ORDER BY u.name
            """), {"e": event_id}).mappings().all()

            member_count = con.execute(text("""
              SELECT COUNT(*) FROM club_members WHERE club_id=:c
            """), {"c": ev["club_id"]}).scalar() or 0

            events_all = con.execute(text("""
              SELECT id, title, COALESCE(starts_at, created_at) AS tkey, created_at
              FROM events WHERE club_id=:c ORDER BY COALESCE(starts_at, created_at) ASC, id ASC
            """), {"c": ev["club_id"]}).mappings().all()

            cur_key = ev["starts_at"] if ev["starts_at"] else ev["created_at"]
            next_id = None
            for e in events_all:
                if e["id"] == ev["id"]: continue
                if e["tkey"] and cur_key and e["tkey"] > cur_key:
                    next_id = e["id"]; break
            if not next_id and len(events_all) >= 2:
                ids = [x["id"] for x in events_all]
                try:
                    idx = ids.index(ev["id"])
                    if idx < len(ids) - 1: next_id = ids[idx+1]
                except ValueError:
                    pass

            total_att = len(attendees)
            edu_verified = sum(1 for a in attendees if a.get("edu_email"))

            continued = 0
            if next_id and total_att > 0:
                ids = [str(a["id"]) for a in attendees]
                placeholders = ",".join(ids) if ids else "0"
                q = text(f"SELECT COUNT(*) FROM checkins WHERE event_id=:ne AND user_id IN ({placeholders})")
                continued = con.execute(q, {"ne": next_id}).scalar() or 0

            new_edges_after = con.execute(text("""
              SELECT COUNT(*) FROM graph_edges 
              WHERE club_id=:c AND status='accepted' AND created_at >= :t0
            """), {"c": ev["club_id"], "t0": ev["created_at"]}).scalar() or 0

        att_rate = (total_att / member_count * 100.0) if member_count else 0.0
        cont_rate = (continued / total_att * 100.0) if total_att else 0.0

        return render_template("event_analytics.html",
                               user=user, club=club, event=ev,
                               attendees=attendees,
                               member_count=member_count,
                               total_att=total_att,
                               att_rate=att_rate,
                               edu_verified=edu_verified,
                               new_edges_after=new_edges_after,
                               continued=continued,
                               cont_rate=cont_rate)

    @app.get("/events/<int:event_id>/export.csv")
    def event_export_csv(event_id):
        user = current_user()
        if not user: return redirect(url_for("li_login", next=request.url))
        with engine.begin() as con:
            ev = con.execute(text("SELECT * FROM events WHERE id=:id"), {"id": event_id}).mappings().first()
            if not ev: abort(404)
            if not is_admin_or_owner(ev["club_id"], user["id"]):
                flash("Bu etkinliğin verilerini indirme yetkin yok.", "danger")
                return redirect(url_for("club_detail", club_id=ev["club_id"]))
            rows = con.execute(text("""
              SELECT u.name, u.edu_email, u.avatar_url, ci.checked_at
              FROM checkins ci JOIN users u ON u.id=ci.user_id
              WHERE ci.event_id=:e
              ORDER BY u.name
            """), {"e": event_id}).all()

        def generate():
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(["Name", "EDU Email", "Avatar URL", "Checked At (local)"])
            yield output.getvalue(); output.seek(0); output.truncate(0)
            for r in rows:
                writer.writerow([r[0], r[1] or "", r[2] or "", ts2human(r[3])])
                yield output.getvalue(); output.seek(0); output.truncate(0)

        filename = f"event_{event_id}_checkins.csv"
        return Response(generate(), mimetype="text/csv",
                        headers={"Content-Disposition": f"attachment; filename={filename}"})

    @app.get("/clubs/<int:club_id>/analytics")
    def club_analytics(club_id):
        user = current_user()
        if not user: return redirect(url_for("li_login", next=request.url))
        if not is_admin_or_owner(club_id, user["id"]):
            flash("Kulüp analitiğine erişimin yok.", "danger")
            return redirect(url_for("club_detail", club_id=club_id))

        with engine.begin() as con:
            club = con.execute(text("SELECT * FROM clubs WHERE id=:c"), {"c": club_id}).mappings().first()

            events = con.execute(text("""
              SELECT e.id, e.title, e.starts_at, e.created_at,
                     COALESCE(e.starts_at, e.created_at) AS tkey,
                     (SELECT COUNT(*) FROM checkins ci WHERE ci.event_id=e.id) AS checkin_count
              FROM events e 
              WHERE e.club_id=:c 
              ORDER BY COALESCE(e.starts_at, e.created_at) ASC, e.id ASC
            """), {"c": club_id}).mappings().all()

            member_count = con.execute(text("SELECT COUNT(*) FROM club_members WHERE club_id=:c"),
                                       {"c": club_id}).scalar() or 0

            event_ids = [e["id"] for e in events]
            attendees_by_event = {eid: set() for eid in event_ids}
            if event_ids:
                placeholders = ",".join([str(eid) for eid in event_ids])
                q = text(f"""
                    SELECT event_id, user_id FROM checkins 
                    WHERE event_id IN ({placeholders})
                """)
                allcis = con.execute(q).all()
                for ev_id, uid in allcis:
                    attendees_by_event[ev_id].add(uid)

            retention_pairs = []
            for i in range(len(events)-1):
                a = attendees_by_event.get(events[i]["id"], set())
                b = attendees_by_event.get(events[i+1]["id"], set())
                rate = (len(a & b) / len(a) * 100.0) if a else 0.0
                retention_pairs.append({
                    "from_event_id": events[i]["id"],
                    "to_event_id": events[i+1]["id"],
                    "from_title": events[i]["title"],
                    "to_title": events[i+1]["title"],
                    "rate": rate,
                    "from_count": len(a),
                    "both_count": len(a & b)
                })
            avg_retention = (sum(p["rate"] for p in retention_pairs) / len(retention_pairs)) if retention_pairs else 0.0

            active_user_ids = set()
            for s in attendees_by_event.values():
                active_user_ids |= s
            users_meta = {}
            if active_user_ids:
                placeholders = ",".join([str(uid) for uid in active_user_ids])
                uq = text(f"SELECT id, name, avatar_url FROM users WHERE id IN ({placeholders})")
                for r in con.execute(uq).all():
                    users_meta[r[0]] = {"id": r[0], "name": r[1], "avatar_url": r[2]}
            heatmap_rows = []
            for uid in sorted(list(active_user_ids)):
                row = {
                    "user_id": uid,
                    "name": users_meta.get(uid, {}).get("name", f"User {uid}"),
                    "avatar_url": users_meta.get(uid, {}).get("avatar_url"),
                    "attends": []
                }
                for e in events:
                    row["attends"].append(1 if uid in attendees_by_event.get(e["id"], set()) else 0)
                heatmap_rows.append(row)

            active_counts = []
            for uid in active_user_ids:
                cnt = sum(1 for ev_id in event_ids if uid in attendees_by_event.get(ev_id, set()))
                active_counts.append((uid, cnt))
            active_counts.sort(key=lambda x: x[1], reverse=True)
            top_participants = []
            for uid, cnt in active_counts[:5]:
                meta = users_meta.get(uid, {"name": f"User {uid}"})
                top_participants.append({"user_id": uid, "name": meta.get("name"), "avatar_url": meta.get("avatar_url"), "count": cnt})

            degrees = {}
            edges = con.execute(text("""
                SELECT src_user_id, dst_user_id FROM graph_edges 
                WHERE club_id=:c AND status='accepted'
            """), {"c": club_id}).all()
            for s, d in edges:
                degrees[s] = degrees.get(s, 0) + 1
                degrees[d] = degrees.get(d, 0) + 1
            degree_sorted = sorted(degrees.items(), key=lambda x: x[1], reverse=True)
            top_connectors = []
            for uid, deg in degree_sorted[:5]:
                meta = users_meta.get(uid)
                if not meta:
                    m = con.execute(text("SELECT name, avatar_url FROM users WHERE id=:i"), {"i": uid}).first()
                    meta = {"name": m[0] if m else f"User {uid}", "avatar_url": m[1] if m else None}
                top_connectors.append({"user_id": uid, "name": meta["name"], "avatar_url": meta["avatar_url"], "degree": deg})

        trend = [{"event_id": e["id"], "title": e["title"], "t": e["tkey"], "count": e["checkin_count"]} for e in events]
        total_events = len(events)
        total_checkins = sum(e["checkin_count"] for e in events)
        unique_attendees = len(active_user_ids)
        repeaters = sum(1 for _, c in active_counts if c >= 2)

        return render_template("club_analytics.html",
                               user=user, club=club, events=events,
                               member_count=member_count,
                               trend=trend,
                               total_events=total_events,
                               total_checkins=total_checkins,
                               unique_attendees=unique_attendees,
                               repeaters=repeaters,
                               avg_retention=avg_retention,
                               retention_pairs=retention_pairs,
                               heatmap_rows=heatmap_rows,
                               top_participants=top_participants,
                               top_connectors=top_connectors)

    @app.context_processor
    def inject_globals():
        return {"HOST_URL": app.config["HOST_URL"]}

    return app

app = create_app()

if __name__ == "__main__":
    port = int(os.getenv("PORT", "8000"))
    app.run(host="0.0.0.0", port=port, debug=False, use_reloader=False)

