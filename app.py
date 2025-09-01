# app.py
from __future__ import annotations
import os
import re
import json
import time
import hmac
import base64
import hashlib
import secrets
from datetime import datetime, timezone
from urllib.parse import urlencode

import requests
from flask import (
    Flask, request, redirect, url_for, session,
    render_template, abort, jsonify, make_response, flash
)
from sqlalchemy import (
    create_engine, func, select, text, String, Integer, DateTime, Boolean,
    ForeignKey, UniqueConstraint, and_, or_
)
from sqlalchemy.orm import (
    DeclarativeBase, Mapped, mapped_column, relationship, Session
)

# -------------------------
# Config / App Factory
# -------------------------
def env_bool(name: str, default: bool = False) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return str(v).lower() in {"1", "true", "yes", "on"}

def now_utc() -> datetime:
    return datetime.now(timezone.utc)

class Base(DeclarativeBase):
    pass

class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    li_id: Mapped[str | None] = mapped_column(String(128), unique=True)
    name: Mapped[str] = mapped_column(String(200))
    email: Mapped[str | None] = mapped_column(String(320))
    avatar_url: Mapped[str | None] = mapped_column(String(500))
    edu_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)

    memberships: Mapped[list["Membership"]] = relationship(back_populates="user")
    owned_clubs: Mapped[list["Club"]] = relationship(back_populates="owner", cascade="all, delete")
    sent_connections: Mapped[list["Connection"]] = relationship(
        foreign_keys="Connection.a_id", back_populates="a", cascade="all, delete-orphan"
    )
    received_connections: Mapped[list["Connection"]] = relationship(
        foreign_keys="Connection.b_id", back_populates="b", cascade="all, delete-orphan"
    )

class Club(Base):
    __tablename__ = "clubs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(200), unique=True)
    description: Mapped[str | None] = mapped_column(String(1000))
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)

    owner: Mapped[User] = relationship(back_populates="owned_clubs")
    memberships: Mapped[list["Membership"]] = relationship(back_populates="club", cascade="all, delete")
    events: Mapped[list["Event"]] = relationship(back_populates="club", cascade="all, delete")

class Membership(Base):
    __tablename__ = "memberships"
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), primary_key=True)
    club_id: Mapped[int] = mapped_column(ForeignKey("clubs.id"), primary_key=True)
    role: Mapped[str] = mapped_column(String(50), default="member")
    joined_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)

    user: Mapped[User] = relationship(back_populates="memberships")
    club: Mapped[Club] = relationship(back_populates="memberships")

class Event(Base):
    __tablename__ = "events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    club_id: Mapped[int] = mapped_column(ForeignKey("clubs.id"))
    title: Mapped[str] = mapped_column(String(200))
    starts_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    qr_secret: Mapped[str] = mapped_column(String(64), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)

    club: Mapped[Club] = relationship(back_populates="events")
    checkins: Mapped[list["Checkin"]] = relationship(back_populates="event", cascade="all, delete")

class Checkin(Base):
    __tablename__ = "checkins"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    event_id: Mapped[int] = mapped_column(ForeignKey("events.id"), index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    __table_args__ = (UniqueConstraint("event_id", "user_id", name="uq_checkin_event_user"),)

    event: Mapped[Event] = relationship(back_populates="checkins")

class Connection(Base):
    __tablename__ = "connections"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    a_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)  # requester
    b_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)  # target
    status: Mapped[str] = mapped_column(String(20), default="pending")  # pending | accepted
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    __table_args__ = (UniqueConstraint("a_id", "b_id", name="uq_conn_pair"),)

    a: Mapped[User] = relationship(foreign_keys=[a_id], back_populates="sent_connections")
    b: Mapped[User] = relationship(foreign_keys=[b_id], back_populates="received_connections")


def create_app() -> Flask:
    app = Flask(__name__, static_folder="static", template_folder="templates")
    app.secret_key = os.getenv("SECRET_KEY", secrets.token_hex(16))

    # ENV
    app.config["HOST_URL"] = os.getenv("HOST_URL", "http://localhost:8000").rstrip("/")
    app.config["VERIFY_SSL"] = env_bool("VERIFY_SSL", True)
    app.config["EDU_ALLOWED_DOMAINS"] = [d.strip().lower() for d in os.getenv("EDU_ALLOWED_DOMAINS", "").split(",") if d.strip()]
    app.config["FLASK_ENV"] = os.getenv("FLASK_ENV", "production")

    # DB engine
    db_url = os.getenv("DATABASE_URL", "sqlite:///enfekte.db")
    # SQLAlchemy engine
    engine = create_engine(db_url, pool_pre_ping=True)
    app.engine = engine  # attach for usage

    # Create tables portable (SQLite/Postgres)
    Base.metadata.create_all(engine)

    # -------------------------
    # Helpers
    # -------------------------
    def current_user(session_db: Session) -> User | None:
        uid = session.get("uid")
        if not uid:
            return None
        return session_db.get(User, uid)

    def require_login():
        if not session.get("uid"):
            return redirect(url_for("index"))

    def allowed_edu(email: str | None) -> bool:
        if not email:
            return False
        if not app.config["EDU_ALLOWED_DOMAINS"]:
            return True
        try:
            domain = email.split("@", 1)[1].lower()
        except Exception:
            return False
        return any(domain == d or domain.endswith("." + d) for d in app.config["EDU_ALLOWED_DOMAINS"])

    # -------------------------
    # Index / Health
    # -------------------------
    @app.get("/health")
    def health():
        return jsonify(ok=True, ts=int(time.time()))

    @app.get("/")
    def index():
        try:
            return render_template("index.html")
        except Exception:
            return jsonify({
                "message": "enfekte.co",
                "actions": {
                    "linkedin_login": url_for("li_login", _external=True),
                }
            })

    # -------------------------
    # LinkedIn OIDC Login
    # -------------------------
    LI_AUTH = "https://www.linkedin.com/oauth/v2/authorization"
    LI_TOKEN = "https://www.linkedin.com/oauth/v2/accessToken"
    LI_USERINFO = "https://api.linkedin.com/v2/userinfo"

    def make_redirect_uri() -> str:
        return f'{app.config["HOST_URL"]}/auth/linkedin/callback'

    @app.get("/auth/linkedin/login")
    def li_login():
        client_id = os.getenv("LINKEDIN_CLIENT_ID")
        if not client_id:
            return "LinkedIn client id missing", 500
        state = secrets.token_urlsafe(16)
        nonce = secrets.token_urlsafe(16)
        session["li_state"] = state
        session["li_nonce"] = nonce
        params = {
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": make_redirect_uri(),
            "scope": "openid profile email",
            "state": state,
            "nonce": nonce,
        }
        return redirect(f"{LI_AUTH}?{urlencode(params)}")

    @app.get("/auth/linkedin/callback")
    def li_callback():
        err = request.args.get("error")
        if err:
            flash(f"LinkedIn error: {err}", "error")
            return redirect(url_for("index"))

        code = request.args.get("code")
        state = request.args.get("state")
        if not code or not state:
            flash("Invalid callback", "error")
            return redirect(url_for("index"))

        if state != session.get("li_state"):
            flash("State mismatch", "error")
            return redirect(url_for("index"))

        # Exchange code
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": make_redirect_uri(),
            "client_id": os.getenv("LINKEDIN_CLIENT_ID"),
            "client_secret": os.getenv("LINKEDIN_CLIENT_SECRET"),
        }
        try:
            tresp = requests.post(LI_TOKEN, data=data, timeout=20, verify=app.config["VERIFY_SSL"])
            tresp.raise_for_status()
            token = tresp.json()
        except Exception as e:
            flash(f"Token exchange failed: {e}", "error")
            return redirect(url_for("index"))

        access_token = token.get("access_token")
        if not access_token:
            flash("Missing access_token", "error")
            return redirect(url_for("index"))

        # Get userinfo
        headers = {"Authorization": f"Bearer {access_token}"}
        userinfo = None
        try:
            uresp = requests.get(LI_USERINFO, headers=headers, timeout=15, verify=app.config["VERIFY_SSL"])
            if uresp.ok:
                userinfo = uresp.json()
        except Exception:
            userinfo = None

        # Fallback to v2 endpoints (public profile/email) if needed
        if not userinfo:
            try:
                me = requests.get(
                    "https://api.linkedin.com/v2/me",
                    headers=headers,
                    params={"projection": "(id,localizedFirstName,localizedLastName,profilePicture(displayImage~:playableStreams))"},
                    timeout=15, verify=app.config["VERIFY_SSL"],
                )
                email = requests.get(
                    "https://api.linkedin.com/v2/emailAddress",
                    headers=headers,
                    params={"q": "members", "projection": "(elements*(handle~))"},
                    timeout=15, verify=app.config["VERIFY_SSL"],
                )
                if me.ok:
                    me_j = me.json()
                    email_j = email.json() if email.ok else {}
                    primary_email = None
                    try:
                        primary_email = email_j["elements"][0]["handle~"]["emailAddress"]
                    except Exception:
                        pass
                    pic = None
                    try:
                        pics = me_j["profilePicture"]["displayImage~"]["elements"]
                        if pics:
                            # pick highest
                            pic = pics[-1]["identifiers"][0]["identifier"]
                    except Exception:
                        pass
                    userinfo = {
                        "sub": me_j.get("id"),
                        "name": f'{me_j.get("localizedFirstName","")} {me_j.get("localizedLastName","")}'.strip(),
                        "email": primary_email,
                        "picture": pic,
                    }
            except Exception:
                userinfo = None

        if not userinfo:
            flash("LinkedIn userinfo failed", "error")
            return redirect(url_for("index"))

        # Persist / login
        with Session(app.engine) as db:
            li_id = str(userinfo.get("sub") or userinfo.get("id") or "")
            name = (userinfo.get("name") or "").strip() or "LinkedIn User"
            email = (userinfo.get("email") or "").strip() or None
            avatar = userinfo.get("picture") or None

            user = db.scalar(select(User).where(User.li_id == li_id)) if li_id else None
            if not user and email:
                user = db.scalar(select(User).where(User.email == email))
            if not user:
                user = User(li_id=li_id or None, name=name, email=email, avatar_url=avatar, edu_verified=False)
                db.add(user)
                db.flush()
            else:
                user.name = name or user.name
                if email:
                    user.email = email
                if avatar:
                    user.avatar_url = avatar
            # EDU verify fast-path
            if email and allowed_edu(email):
                user.edu_verified = True
            db.commit()
            session["uid"] = user.id

        return redirect(url_for("home"))

    # -------------------------
    # Core pages
    # -------------------------
    @app.get("/home")
    def home():
        require_login()
        with Session(app.engine) as db:
            user = current_user(db)
            my_clubs = db.scalars(select(Club).join(Membership).where(Membership.user_id == user.id)).all()
            owned = db.scalars(select(Club).where(Club.owner_id == user.id)).all()
            try:
                return render_template("home.html", user=user, my_clubs=my_clubs, owned_clubs=owned)
            except Exception:
                return jsonify({
                    "user": {"id": user.id, "name": user.name, "email": user.email, "edu_verified": user.edu_verified},
                    "my_clubs": [{"id": c.id, "name": c.name} for c in my_clubs],
                    "owned_clubs": [{"id": c.id, "name": c.name} for c in owned],
                })

    # -------------------------
    # Clubs / Events
    # -------------------------
    @app.post("/clubs")
    def create_club():
        require_login()
        data = request.get_json(silent=True) or request.form
        name = (data.get("name") or "").strip()
        desc = (data.get("description") or "").strip()
        if not name:
            return jsonify({"error": "name required"}), 400
        with Session(app.engine) as db:
            user = current_user(db)
            club = Club(name=name, description=desc or None, owner_id=user.id)
            db.add(club)
            db.flush()
            db.add(Membership(user_id=user.id, club_id=club.id, role="owner"))
            db.commit()
            return jsonify({"ok": True, "club_id": club.id})

    @app.get("/clubs/<int:club_id>")
    def club_page(club_id: int):
        require_login()
        with Session(app.engine) as db:
            club = db.get(Club, club_id)
            if not club:
                abort(404)
            members = db.scalars(select(User).join(Membership).where(Membership.club_id == club_id)).all()
            events = db.scalars(select(Event).where(Event.club_id == club_id).order_by(Event.starts_at.desc())).all()
            try:
                return render_template("club_new.html", club=club, members=members, events=events)
            except Exception:
                return jsonify({
                    "club": {"id": club.id, "name": club.name, "description": club.description},
                    "members": [{"id": m.id, "name": m.name} for m in members],
                    "events": [{"id": e.id, "title": e.title, "starts_at": e.starts_at.isoformat()} for e in events],
                })

    @app.post("/clubs/<int:club_id>/join")
    def join_club(club_id: int):
        require_login()
        with Session(app.engine) as db:
            user = current_user(db)
            if not db.get(Club, club_id):
                abort(404)
            exists = db.get(Membership, {"user_id": user.id, "club_id": club_id})
            if not exists:
                db.add(Membership(user_id=user.id, club_id=club_id, role="member"))
                db.commit()
            return jsonify({"ok": True})

    @app.post("/clubs/<int:club_id>/events")
    def create_event(club_id: int):
        require_login()
        data = request.get_json(silent=True) or request.form
        title = (data.get("title") or "").strip()
        starts_at_str = (data.get("starts_at") or "").strip()
        if not title or not starts_at_str:
            return jsonify({"error": "title and starts_at required"}), 400
        try:
            starts_at = datetime.fromisoformat(starts_at_str)
            if starts_at.tzinfo is None:
                starts_at = starts_at.replace(tzinfo=timezone.utc)
        except Exception:
            return jsonify({"error": "invalid starts_at"}), 400
        with Session(app.engine) as db:
            user = current_user(db)
            club = db.get(Club, club_id)
            if not club or club.owner_id != user.id:
                return jsonify({"error": "only owner can create events"}), 403
            qr_secret = secrets.token_urlsafe(18)
            ev = Event(club_id=club_id, title=title, starts_at=starts_at, qr_secret=qr_secret)
            db.add(ev)
            db.commit()
            return jsonify({"ok": True, "event_id": ev.id})

    # -------------------------
    # QR & Check-in
    # -------------------------
    @app.get("/events/<int:event_id>/qr.png")
    def event_qr(event_id: int):
        from io import BytesIO
        import qrcode
        with Session(app.engine) as db:
            ev = db.get(Event, event_id)
            if not ev:
                abort(404)
            join_url = f'{app.config["HOST_URL"]}/join?e={ev.id}&q={ev.qr_secret}'
            img = qrcode.make(join_url)
            buf = BytesIO()
            img.save(buf, format="PNG")
            buf.seek(0)
            resp = make_response(buf.read())
            resp.headers["Content-Type"] = "image/png"
            return resp

    @app.get("/join")
    def join_event():
        require_login()
        e = request.args.get("e", type=int)
        q = request.args.get("q", type=str)
        if not e or not q:
            abort(400)
        with Session(app.engine) as db:
            ev = db.get(Event, e)
            if not ev or ev.qr_secret != q:
                return "Invalid QR", 400
            user = current_user(db)
            # ensure membership
            mem = db.get(Membership, {"user_id": user.id, "club_id": ev.club_id})
            if not mem:
                db.add(Membership(user_id=user.id, club_id=ev.club_id, role="member"))
                db.flush()
            # checkin (on conflict ignore)
            exists = db.scalar(select(Checkin.id).where(Checkin.event_id == e, Checkin.user_id == user.id))
            if not exists:
                db.add(Checkin(event_id=e, user_id=user.id))
                db.commit()
            return redirect(url_for("club_page", club_id=ev.club_id))

    # -------------------------
    # Connections (Request / Accept)
    # -------------------------
    @app.post("/connect/request/<int:target_id>")
    def connect_request(target_id: int):
        require_login()
        with Session(app.engine) as db:
            me = current_user(db)
            if me.id == target_id:
                return jsonify({"error": "cannot connect to self"}), 400
            # normalize pair order? we keep directed request (a=me,b=target)
            existing = db.scalar(select(Connection).where(
                or_(
                    and_(Connection.a_id == me.id, Connection.b_id == target_id),
                    and_(Connection.a_id == target_id, Connection.b_id == me.id),
                )
            ))
            if existing:
                return jsonify({"ok": True, "status": existing.status, "connection_id": existing.id})
            c = Connection(a_id=me.id, b_id=target_id, status="pending")
            db.add(c)
            db.commit()
            return jsonify({"ok": True, "connection_id": c.id, "status": "pending"})

    @app.post("/connect/accept/<int:connection_id>")
    def connect_accept(connection_id: int):
        require_login()
        with Session(app.engine) as db:
            me = current_user(db)
            c = db.get(Connection, connection_id)
            if not c:
                abort(404)
            if c.b_id != me.id:
                return jsonify({"error": "not your request"}), 403
            c.status = "accepted"
            db.commit()
            return jsonify({"ok": True})

    # -------------------------
    # Community Graph (club)
    # -------------------------
    @app.get("/clubs/<int:club_id>/graph.json")
    def club_graph_json(club_id: int):
        require_login()
        with Session(app.engine) as db:
            # nodes: all club members
            members = db.scalars(select(User).join(Membership).where(Membership.club_id == club_id)).all()
            ids = [m.id for m in members]
            # edges: accepted connections where both ends in the club
            edges = []
            if ids:
                # both directions accepted treated as one undirected edge
                conns = db.scalars(
                    select(Connection).where(
                        Connection.status == "accepted",
                        Connection.a_id.in_(ids),
                        Connection.b_id.in_(ids),
                    )
                ).all()
                for c in conns:
                    edges.append({"source": c.a_id, "target": c.b_id})
            data = {
                "nodes": [{"id": u.id, "name": u.name, "avatar": u.avatar_url} for u in members],
                "links": edges,
            }
            return jsonify(data)

    @app.get("/clubs/<int:club_id>/graph")
    def club_graph_page(club_id: int):
        require_login()
        try:
            return render_template("community_graph.html", club_id=club_id)
        except Exception:
            return redirect(url_for("club_graph_json", club_id=club_id))

    # -------------------------
    # Analytics
    # -------------------------
    @app.get("/events/<int:event_id>/analytics")
    def event_analytics(event_id: int):
        require_login()
        with Session(app.engine) as db:
            ev = db.get(Event, event_id)
            if not ev:
                abort(404)
            # total attendees
            total = db.scalar(select(func.count()).select_from(Checkin).where(Checkin.event_id == event_id)) or 0

            # find next event of same club (by time)
            next_ev = db.scalar(
                select(Event.id).where(Event.club_id == ev.club_id, Event.starts_at > ev.starts_at).order_by(Event.starts_at.asc())
            )
            continued_count = 0
            if next_ev:
                uids = db.scalars(select(Checkin.user_id).where(Checkin.event_id == event_id)).all()
                if uids:
                    continued_count = db.scalar(
                        select(func.count()).select_from(Checkin).where(
                            Checkin.event_id == next_ev, Checkin.user_id.in_(uids)
                        )
                    ) or 0

            data = {
                "event": {"id": ev.id, "title": ev.title, "starts_at": ev.starts_at.isoformat()},
                "attendees": total,
                "continued_to_next": continued_count,
            }
            return jsonify(data)

    @app.get("/clubs/<int:club_id>/analytics")
    def club_analytics(club_id: int):
        require_login()
        with Session(app.engine) as db:
            club = db.get(Club, club_id)
            if not club:
                abort(404)

            # events
            evs = db.scalars(select(Event.id, Event.starts_at).where(Event.club_id == club_id).order_by(Event.starts_at.asc())).all()
            event_ids = [e[0] for e in evs]
            # attendees per event
            per_event = {}
            if event_ids:
                rows = db.execute(
                    select(Checkin.event_id, func.count())
                    .where(Checkin.event_id.in_(event_ids))
                    .group_by(Checkin.event_id)
                ).all()
                for eid, cnt in rows:
                    per_event[eid] = int(cnt)

            # active members (any checkin)
            active_user_ids = []
            if event_ids:
                active_user_ids = [r[0] for r in db.execute(
                    select(Checkin.user_id).where(Checkin.event_id.in_(event_ids)).group_by(Checkin.user_id)
                ).all()]

            # last activity per user
            last_activity = {}
            if active_user_ids:
                rows = db.execute(
                    select(Checkin.user_id, func.max(Checkin.created_at))
                    .where(Checkin.user_id.in_(active_user_ids))
                    .group_by(Checkin.user_id)
                ).all()
                for uid, ts in rows:
                    last_activity[uid] = ts.isoformat() if isinstance(ts, datetime) else str(ts)

            # assemble
            out = {
                "club": {"id": club.id, "name": club.name},
                "events": [{"id": eid, "starts_at": sa.isoformat(), "attendees": per_event.get(eid, 0)} for eid, sa in evs],
                "active_members": len(active_user_ids),
                "last_activity": last_activity,
            }
            return jsonify(out)

    # -------------------------
    # Simple views
    # -------------------------
    @app.get("/login")
    def login_page():
        try:
            return render_template("login.html")
        except Exception:
            return redirect(url_for("li_login"))

    @app.get("/logout")
    def logout():
        session.clear()
        return redirect(url_for("index"))

    return app


app = create_app()

if __name__ == "__main__":
    port = int(os.getenv("PORT", "8000"))
    debug = os.getenv("FLASK_ENV", "production") != "production"
    app.run(host="0.0.0.0", port=port, debug=debug, use_reloader=debug)

