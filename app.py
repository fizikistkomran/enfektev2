from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
import os, random, colorsys, re, json, time
import psycopg2
from psycopg2.extras import RealDictCursor
from collections import defaultdict
from datetime import datetime
from urllib.parse import urlparse

app = Flask(__name__)
# Güvenlik: SECRET_KEY'i env'den al; yoksa mevcut değerine düş
app.secret_key = os.getenv('SECRET_KEY', 'super-secret-key')

# -----------------------------------------------------------
# DB helpers
# -----------------------------------------------------------
def _parse_database_url(url: str):
    """
    DATABASE_URL=postgresql://user:pass@host:port/dbname
    """
    parsed = urlparse(url)
    return {
        "dbname": parsed.path.lstrip('/'),
        "user": parsed.username,
        "password": parsed.password,
        "host": parsed.hostname,
        "port": parsed.port or 5432,
    }

def get_db_connection():
    """
    Önce env DATABASE_URL varsa onu kullan,
    yoksa mevcut sabit Railway proxy bilgilerine düş.
    Kısa timeout + opsiyonel SSL.
    """
    conn_kwargs = {}
    if os.getenv("DATABASE_URL"):
        conn_kwargs = _parse_database_url(os.getenv("DATABASE_URL"))
    else:
        # Mevcut sabitler (geri uyumluluk)
        conn_kwargs = dict(
            dbname="railway",
            user="postgres",
            password="BuYuHoBHNkQNGxbQHDGNCVrYtnLWhIvo",
            host="hopper.proxy.rlwy.net",
            port=36466,
        )

    # Ortak seçenekler
    conn_kwargs.update(
        dict(
            cursor_factory=RealDictCursor,
            connect_timeout=5,   # hızlı timeout
        )
    )

    # SSL (Railway çoğunlukla ister)
    verify_ssl = os.getenv("VERIFY_SSL", "true").lower() == "true"
    if verify_ssl:
        conn_kwargs["sslmode"] = "require"

    return psycopg2.connect(**conn_kwargs)

def init_db():
    """
    Tablo kurulumunu dener; başarısız olsa da uygulamayı kilitlemesin.
    """
    try:
        with get_db_connection() as conn:
            with conn.cursor() as c:
                c.execute('''
                    CREATE TABLE IF NOT EXISTS users (
                        id SERIAL PRIMARY KEY,
                        name TEXT UNIQUE,
                        slug TEXT UNIQUE,
                        password TEXT
                    )
                ''')
                c.execute('''
                    CREATE TABLE IF NOT EXISTS connections (
                        id SERIAL PRIMARY KEY,
                        owner_id INTEGER,
                        visitor_name TEXT,
                        connection_type TEXT,
                        connector_name TEXT
                    )
                ''')
            conn.commit()
    except Exception as e:
        # Boot'u bloklamayalım; log'la geç
        print("[WARN] init_db skipped due to error:", e)

# -----------------------------------------------------------
# Utilities
# -----------------------------------------------------------
def slugify(text):
    mapping = {
        'ç': 'c', 'ğ': 'g', 'ı': 'i', 'ö': 'o', 'ş': 's', 'ü': 'u',
        'Ç': 'c', 'Ğ': 'g', 'İ': 'i', 'Ö': 'o', 'Ş': 's', 'Ü': 'u'
    }
    for src, target in mapping.items():
        text = text.replace(src, target)
    text = text.lower()
    text = re.sub(r'[^\w\s-]', '', text)
    text = re.sub(r'\s+', '-', text)
    return text.strip('-')

def normalize_name(name):
    mapping = {
        'ç': 'c', 'ğ': 'g', 'ı': 'i', 'ö': 'o', 'ş': 's', 'ü': 'u',
        'Ç': 'c', 'Ğ': 'g', 'İ': 'i', 'Ö': 'o', 'Ş': 's', 'Ü': 'u',
        'I': 'i'
    }
    for src, target in mapping.items():
        name = name.replace(src, target)
    return name.lower().strip()

def random_color():
    h, s, v = random.random(), 0.5 + random.random() * 0.5, 0.7 + random.random() * 0.3
    r, g, b = colorsys.hsv_to_rgb(h, s, v)
    return f'rgb({int(r*255)}, {int(g*255)}, {int(b*255)})'

def mix_colors(colors):
    if not colors:
        return "#cccccc"
    total_r, total_g, total_b, valid_count = 0, 0, 0, 0
    for col in colors:
        try:
            if col.startswith("rgb(") and col.endswith(")"):
                r, g, b = map(int, col[4:-1].split(','))
                total_r += r; total_g += g; total_b += b
                valid_count += 1
        except Exception:
            continue
    if valid_count == 0:
        return "#cccccc"
    return f"rgb({total_r // valid_count}, {total_g // valid_count}, {total_b // valid_count})"

def fixed_color(user_id):
    palette = [
        "#4CAF50", "#81C784", "#66BB6A", "#388E3C", "#2E7D32",
        "#1B5E20", "#A5D6A7", "#43A047", "#00796B", "#33691E"
    ]
    return palette[user_id % len(palette)]

def build_graph_multi(rows, user_rows):
    owner_to_rows = defaultdict(list)
    for row in rows:
        if 'owner_id' in row:
            owner_to_rows[row['owner_id']].append((row['visitor_name'], row['connection_type'], row['connector_name']))

    user_id_to_name = {u['id']: u['name'] for u in user_rows}
    user_name_to_slug = {u['name']: u['slug'] for u in user_rows}
    user_id_to_color = {u['id']: fixed_color(u['id']) for u in user_rows}

    name_to_owners = defaultdict(set)
    all_edges = set()

    for owner_id, conns in owner_to_rows.items():
        owner_name = user_id_to_name.get(owner_id, f"user_{owner_id}")
        name_to_connector = {v: (t, c) for v, t, c in conns}
        for visitor in name_to_connector:
            person, chain = visitor, []
            while True:
                ctype, connector = name_to_connector.get(person, (None, None))
                if connector and connector != person:
                    chain.append((person, connector))
                    person = connector
                else:
                    break
            if chain:
                all_edges.add((chain[-1][1], owner_name))
            else:
                all_edges.add((visitor, owner_name))
            all_edges.update(chain)
            for n in [visitor] + [c for _, c in chain] + [owner_name]:
                name_to_owners[n].add(owner_id)

    all_nodes = {n for edge in all_edges for n in edge}
    name_to_id = {name: i + 1 for i, name in enumerate(sorted(all_nodes))}

    nodes_vis = []
    for name, nid in name_to_id.items():
        owners = name_to_owners.get(name, set())
        colors = [user_id_to_color[o] for o in owners if o in user_id_to_color]
        color = colors[0] if len(colors) == 1 else mix_colors(colors)
        node = {"id": nid, "label": name, "color": color}
        if name in user_name_to_slug:
            node["slug"] = user_name_to_slug[name]
        nodes_vis.append(node)

    edges_vis = [{"from": name_to_id[f], "to": name_to_id[t]} for f, t in all_edges]
    return nodes_vis, edges_vis

# -----------------------------------------------------------
# Health / Ping (edge 502 için kritik)
# -----------------------------------------------------------
@app.get("/health")
def health():
    return jsonify(status="ok", ts=int(time.time()))

@app.get("/__ping")
def ping():
    return "PONG", 200, {"Content-Type": "text/plain; charset=utf-8"}

# -----------------------------------------------------------
# Routes
# -----------------------------------------------------------
@app.route('/')
def home():
    with get_db_connection() as conn:
        with conn.cursor() as c:
            c.execute("SELECT * FROM connections")
            conn_rows = c.fetchall()
            c.execute("SELECT id, name, slug FROM users")
            user_rows = c.fetchall()
    nodes, edges = build_graph_multi(conn_rows, user_rows)
    return render_template("home.html", nodes=nodes, edges=edges)

@app.route('/suggest')
def suggest():
    query = request.args.get('q', '').lower()
    if not query:
        return jsonify(results=[])
    with get_db_connection() as conn:
        with conn.cursor() as c:
            c.execute("SELECT name, slug FROM users WHERE LOWER(name) LIKE %s LIMIT 10", (f"%{query}%",))
            users = c.fetchall()
    return jsonify(results=users)

@app.route('/create', methods=['GET', 'POST'])
def create():
    if request.method == 'POST':
        name = request.form['name']
        slug = slugify(name)
        password = generate_password_hash(request.form['password'])
        with get_db_connection() as conn:
            with conn.cursor() as c:
                try:
                    c.execute("INSERT INTO users (name, slug, password) VALUES (%s, %s, %s)", (name, slug, password))
                    conn.commit()
                except psycopg2.errors.UniqueViolation:
                    conn.rollback()
                    return "Bu isim veya slug zaten alınmış."
        return redirect(url_for('login', slug=slug))
    return render_template("create.html")

@app.route('/merge-connectors')
def merge_connectors():
    with get_db_connection() as conn:
        with conn.cursor() as c:
            c.execute('''
                UPDATE connections
                SET connector_id = users.id
                FROM users
                WHERE connections.connector_name = users.name
            ''')
            conn.commit()
    return "Connector ID'ler başarıyla güncellendi."

@app.route('/fix-visitor-ids')
def fix_visitor_ids():
    with get_db_connection() as conn:
        with conn.cursor() as c:
            c.execute('''
                UPDATE connections
                SET visitor_id = users.id
                FROM users
                WHERE connections.visitor_name = users.name
            ''')
            conn.commit()
    return "visitor_id alanları eşleştirildi!"

@app.route('/normalize-all')
def normalize_all():
    def normalize(name):
        mapping = {
            'ç': 'c', 'ğ': 'g', 'ı': 'i', 'ö': 'o', 'ş': 's', 'ü': 'u',
            'Ç': 'c', 'Ğ': 'g', 'İ': 'i', 'Ö': 'o', 'Ş': 's', 'Ü': 'u',
            'I': 'i'
        }
        for src, target in mapping.items():
            name = name.replace(src, target)
        return re.sub(r'[^\w\s-]', '', name.lower().strip())

    with get_db_connection() as conn:
        with conn.cursor() as c:
            c.execute("SELECT id, name FROM users")
            users = c.fetchall()
            for user in users:
                norm_name = normalize(user['name'])
                c.execute("UPDATE users SET name = %s WHERE id = %s", (norm_name, user['id']))

            c.execute("SELECT id, visitor_name FROM connections")
            visitors = c.fetchall()
            for v in visitors:
                norm_visitor = normalize(v['visitor_name'])
                c.execute("UPDATE connections SET visitor_name = %s WHERE id = %s", (norm_visitor, v['id']))

            c.execute("SELECT id, connector_name FROM connections WHERE connector_name IS NOT NULL")
            connectors = c.fetchall()
            for conn_row in connectors:
                norm_connector = normalize(conn_row['connector_name'])
                c.execute("UPDATE connections SET connector_name = %s WHERE id = %s", (norm_connector, conn_row['id']))

            conn.commit()

    return "Tüm kullanıcı ve bağlantı isimleri normalize edildi."

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        name = request.form['name']
        password = request.form['password']
        slug = slugify(name)
        with get_db_connection() as conn:
            with conn.cursor() as c:
                c.execute("SELECT id, password FROM users WHERE slug = %s", (slug,))
                user = c.fetchone()
                if user and check_password_hash(user['password'], password):
                    session['user_id'] = user['id']
                    return redirect(url_for('edit_page', slug=slug))
                else:
                    return "İsim veya şifre hatalı."
    return render_template("login.html")

@app.route('/<slug>', methods=['GET', 'POST'])
def user_page(slug):
    with get_db_connection() as conn:
        with conn.cursor() as c:
            c.execute("SELECT id, name FROM users WHERE slug = %s", (slug,))
            user = c.fetchone()
            if not user:
                return "Kullanıcı bulunamadı"
            owner_id, owner_name = user['id'], user['name']

            if request.method == 'POST' and session.get('user_id') != owner_id:
                visitor_name = request.form['name']
                connection_type = request.form['type']
                connector_name = request.form.get('connector') or None
                c.execute("SELECT visitor_name FROM connections WHERE owner_id = %s", (owner_id,))
                existing = [normalize_name(row['visitor_name']) for row in c.fetchall()]
                if normalize_name(visitor_name) in existing:
                    return f"{visitor_name} zaten eklenmiş."
                c.execute(
                    "INSERT INTO connections (owner_id, visitor_name, connection_type, connector_name) VALUES (%s, %s, %s, %s)",
                    (owner_id, visitor_name, connection_type, connector_name))
                conn.commit()
                return redirect(url_for('user_page', slug=slug))

            c.execute("""
                SELECT * FROM connections 
                WHERE owner_id = %s OR visitor_name = %s OR connector_name = %s
            """, (owner_id, owner_name, owner_name))
            rows = c.fetchall()

            c.execute("SELECT id, name, slug FROM users")
            user_rows = c.fetchall()

    nodes_vis, edges_vis = build_graph_multi(rows, user_rows)
    is_owner = session.get('user_id') == owner_id
    return render_template("user_page.html", nodes=nodes_vis, edges=edges_vis, slug=slug, is_owner=is_owner)

@app.route('/edit/<slug>', methods=['GET', 'POST'])
def edit_page(slug):
    with get_db_connection() as conn:
        with conn.cursor() as c:
            c.execute("SELECT id, name FROM users WHERE slug = %s", (slug,))
            user = c.fetchone()
            if not user:
                return "Kullanıcı bulunamadı"
            owner_id = user['id']
            owner_name = user['name']
            if session.get("user_id") != owner_id:
                return "Yetkisiz giriş"
            if request.method == 'POST':
                conn_id = request.form.get("delete_id")
                if conn_id:
                    c.execute("DELETE FROM connections WHERE id = %s", (conn_id,))
                    conn.commit()
            c.execute("""
                SELECT id, visitor_name, connection_type, connector_name 
                FROM connections 
                WHERE owner_id = %s
                ORDER BY id DESC
            """, (owner_id,))
            connections = c.fetchall()
            c.execute("SELECT visitor_name, connection_type, connector_name FROM connections WHERE owner_id = %s", (owner_id,))
            rows = c.fetchall()
    nodes_vis, edges_vis = build_graph_multi(rows, [{"id": owner_id, "name": owner_name, "slug": slug}])
    return render_template("edit.html", slug=slug, name=owner_name, connections=connections, nodes=nodes_vis, edges=edges_vis)

# -----------------------------------------------------------
# Boot
# -----------------------------------------------------------
init_db()

if __name__ == '__main__':
    # Local çalıştırma için; prod'da gunicorn kullanılıyor.
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "8000")), debug=False)

