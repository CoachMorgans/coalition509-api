"""
Coalition 509 — Backend SaaS
VoteConnect Ecosystem | ChallengeFinancier™
Version : 2.3.3 (Stats résilientes + tables auto)
Auteur  : Coach Morgan's (Simplice KOUAME)
"""

import os
import re
import uuid
import jwt
import psycopg2
import bcrypt
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, g
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash

# ═══════════════════════════════════════════════════════════════════
# CONFIG
# ═══════════════════════════════════════════════════════════════════

app = Flask(__name__)
CORS(app, origins=[
    "https://coachmorgans.github.io",
    "http://localhost:*",
    "https://coalition509-frontend.onrender.com"
], supports_credentials=True)

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'coalition509-dev-secret-key-change-me')
app.config['JWT_EXPIRATION_HOURS'] = 24

DATABASE_URL = os.environ.get('DATABASE_URL')
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL manquante dans les variables d'environnement.")

# ═══════════════════════════════════════════════════════════════════
# DATABASE
# ═══════════════════════════════════════════════════════════════════

def get_db():
    conn = psycopg2.connect(DATABASE_URL)
    conn.autocommit = False
    return conn

def table_exists(cur, table_name):
    cur.execute("""
        SELECT 1 FROM information_schema.tables 
        WHERE table_schema = 'public' AND table_name = %s
    """, [table_name])
    return cur.fetchone() is not None

def init_db():
    try:
        conn = get_db()
        with conn.cursor() as cur:
            # Users
            cur.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    ngd_id VARCHAR(20) UNIQUE,
                    first_name VARCHAR(100) NOT NULL,
                    last_name VARCHAR(100) NOT NULL,
                    phone VARCHAR(20) UNIQUE NOT NULL,
                    email VARCHAR(120),
                    pin_hash VARCHAR(255) NOT NULL,
                    profile_type VARCHAR(50) DEFAULT 'Animateur NGD',
                    role VARCHAR(30) DEFAULT 'user',
                    region VARCHAR(100),
                    commune VARCHAR(100),
                    status VARCHAR(20) DEFAULT 'active',
                    created_at TIMESTAMP DEFAULT NOW(),
                    updated_at TIMESTAMP DEFAULT NOW()
                );
            """)
            # Orders
            cur.execute("""
                CREATE TABLE IF NOT EXISTS orders (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    order_number VARCHAR(30) UNIQUE,
                    user_id UUID REFERENCES users(id),
                    total_amount DECIMAL(12,2) DEFAULT 0,
                    region VARCHAR(100),
                    commune VARCHAR(100),
                    status VARCHAR(20) DEFAULT 'pending',
                    payment_status VARCHAR(20) DEFAULT 'unpaid',
                    created_at TIMESTAMP DEFAULT NOW()
                );
            """)
            # Campaigns
            cur.execute("""
                CREATE TABLE IF NOT EXISTS campaigns (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    name VARCHAR(200) NOT NULL,
                    slug VARCHAR(80) UNIQUE NOT NULL,
                    election_type VARCHAR(50) NOT NULL,
                    region VARCHAR(100) NOT NULL,
                    commune VARCHAR(100),
                    election_date DATE,
                    status VARCHAR(20) DEFAULT 'active',
                    price_ht DECIMAL(12,2) DEFAULT 0,
                    price_tva DECIMAL(12,2) DEFAULT 0,
                    price_total DECIMAL(12,2) DEFAULT 0,
                    pricing_model VARCHAR(30) DEFAULT 'forfait',
                    description TEXT,
                    created_by UUID REFERENCES users(id),
                    created_at TIMESTAMP DEFAULT NOW(),
                    updated_at TIMESTAMP DEFAULT NOW()
                );
            """)
            cur.execute("CREATE INDEX IF NOT EXISTS idx_users_phone ON users(phone);")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_campaigns_status ON campaigns(status);")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_campaigns_region ON campaigns(region);")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_campaigns_created ON campaigns(created_at DESC);")
            conn.commit()
        conn.close()
        app.logger.info("[INIT_DB] Tables OK")
    except Exception as e:
        app.logger.error(f"[INIT_DB] {e}")

# ═══════════════════════════════════════════════════════════════════
# HASH COMPAT — bcrypt (anciens) + werkzeug (nouveaux)
# ═══════════════════════════════════════════════════════════════════

def hash_pin(pin):
    return generate_password_hash(pin)

def verify_pin(pin, stored_hash):
    try:
        if check_password_hash(stored_hash, pin):
            return True
    except Exception:
        pass
    try:
        if bcrypt.checkpw(pin.encode('utf-8'), stored_hash.encode('utf-8')):
            return True
    except Exception:
        pass
    return False

# ═══════════════════════════════════════════════════════════════════
# JWT
# ═══════════════════════════════════════════════════════════════════

def generate_ngd_id():
    return f"NGD-{datetime.now().year}-{uuid.uuid4().hex[:6].upper()}"

def generate_token(user_id):
    payload = {
        'sub': str(user_id),
        'iat': datetime.utcnow(),
        'exp': datetime.utcnow() + timedelta(hours=app.config['JWT_EXPIRATION_HOURS'])
    }
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')

def decode_token(token):
    try:
        return jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

@app.before_request
def jwt_middleware():
    g.current_user = None
    if request.method == 'OPTIONS':
        return
    open_paths = [
        '/api/v1/auth/login',
        '/api/v1/auth/register',
        '/api/auth/verify-bot-token',
        '/health',
        '/'
    ]
    if request.path in open_paths or request.path.endswith('/health'):
        return

    auth_header = request.headers.get('Authorization', '')
    if auth_header.startswith('Bearer '):
        token = auth_header.split(' ')[1]
        decoded = decode_token(token)
        if decoded:
            conn = get_db()
            try:
                with conn.cursor() as cur:
                    cur.execute("""
                        SELECT id, ngd_id, first_name, last_name, phone, email,
                               profile_type, role, region, commune, status
                        FROM users WHERE id = %s
                    """, [decoded['sub']])
                    row = cur.fetchone()
                    if row:
                        g.current_user = {
                            "id": str(row[0]), "ngd_id": row[1], "first_name": row[2],
                            "last_name": row[3], "phone": row[4], "email": row[5],
                            "profile_type": row[6], "role": row[7],
                            "region": row[8], "commune": row[9], "status": row[10]
                        }
            finally:
                conn.close()

# ═══════════════════════════════════════════════════════════════════
# HEALTH
# ═══════════════════════════════════════════════════════════════════

@app.route('/')
def root():
    return jsonify({"status": "Coalition 509 API is running", "version": "2.3.3"})

@app.route('/health')
def health():
    return jsonify({"status": "ok"})

# ═══════════════════════════════════════════════════════════════════
# AUTH
# ═══════════════════════════════════════════════════════════════════

@app.route('/api/v1/auth/register', methods=['POST'])
def register():
    data = request.get_json() or {}
    required = ['first_name', 'last_name', 'phone', 'pin']
    for f in required:
        if not data.get(f):
            return jsonify({"detail": f"Champ obligatoire: {f}"}), 400

    first_name = data['first_name'].strip()
    last_name = data['last_name'].strip()
    phone = re.sub(r'\s+', '', data['phone'])
    pin = data['pin'].strip()
    profile_type = data.get('profile_type', 'Animateur NGD').strip()
    region = data.get('region', '').strip()
    commune = data.get('commune', '').strip()

    if not re.match(r'^\d{4}$', pin):
        return jsonify({"detail": "Le PIN doit contenir exactement 4 chiffres."}), 400

    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM users WHERE phone = %s", [phone])
            if cur.fetchone():
                return jsonify({"detail": "Ce numéro est déjà inscrit."}), 409

            ngd_id = generate_ngd_id()
            pin_hash = hash_pin(pin)
            role = 'admin' if profile_type.lower() in ['coach', 'superadmin'] else 'user'

            cur.execute("""
                INSERT INTO users (ngd_id, first_name, last_name, phone, pin_hash,
                                   profile_type, role, region, commune, status)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, 'active')
                RETURNING id
            """, [ngd_id, first_name, last_name, phone, pin_hash, profile_type, role, region, commune])
            user_id = cur.fetchone()[0]
            conn.commit()

            return jsonify({
                "id": str(user_id), "ngd_id": ngd_id,
                "message": "Inscription réussie"
            }), 201
    except Exception as e:
        conn.rollback()
        return jsonify({"detail": str(e)}), 500
    finally:
        conn.close()

@app.route('/api/v1/auth/login', methods=['POST'])
def login():
    data = request.get_json() or {}
    phone = re.sub(r'\s+', '', data.get('phone', ''))
    pin = data.get('pin', '').strip()

    if not phone or not pin:
        return jsonify({"detail": "Téléphone et PIN requis."}), 400

    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT id, ngd_id, first_name, last_name, phone, email,
                       profile_type, role, region, commune, status, pin_hash
                FROM users WHERE phone = %s
            """, [phone])
            row = cur.fetchone()
            if not row:
                return jsonify({"detail": "Identifiants incorrects."}), 401

            stored_hash = row[11]
            if not verify_pin(pin, stored_hash):
                return jsonify({"detail": "Identifiants incorrects."}), 401

            user = {
                "id": str(row[0]), "ngd_id": row[1], "first_name": row[2],
                "last_name": row[3], "phone": row[4], "email": row[5],
                "profile_type": row[6], "role": row[7],
                "region": row[8], "commune": row[9], "status": row[10]
            }
            token = generate_token(row[0])
            return jsonify({"access_token": token, "user": user}), 200
    except Exception as e:
        return jsonify({"detail": str(e)}), 500
    finally:
        conn.close()

@app.route('/api/v1/auth/me', methods=['GET'])
def me():
    user = getattr(g, 'current_user', None)
    if not user:
        return jsonify({"detail": "Non authentifié."}), 401
    return jsonify(user), 200

@app.route('/api/auth/verify-bot-token', methods=['POST'])
def verify_bot_token():
    data = request.get_json() or {}
    token = data.get('token', '')
    if not token:
        return jsonify({"ok": False, "error": "Token manquant"}), 400

    phone = data.get('phone', '')
    if not phone and '_' in token:
        phone = token.split('_')[0]

    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT id, ngd_id, first_name, last_name, phone, email,
                       profile_type, role, region, commune, status
                FROM users WHERE phone = %s
            """, [phone])
            row = cur.fetchone()
            if row:
                user = {
                    "id": str(row[0]), "ngd_id": row[1], "first_name": row[2],
                    "last_name": row[3], "phone": row[4], "email": row[5],
                    "profile_type": row[6], "role": row[7],
                    "region": row[8], "commune": row[9], "status": row[10]
                }
                return jsonify({"ok": True, "user": user}), 200
            else:
                return jsonify({"ok": True, "needs_registration": True, "phone": phone}), 200
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500
    finally:
        conn.close()

# ═══════════════════════════════════════════════════════════════════
# USERS
# ═══════════════════════════════════════════════════════════════════

@app.route('/api/v1/users', methods=['GET'])
def list_users():
    user = getattr(g, 'current_user', None)
    if not user:
        return jsonify({"detail": "Non authentifié."}), 401

    limit = min(200, request.args.get('limit', 100, type=int))
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT id, ngd_id, first_name, last_name, phone, email,
                       profile_type, role, region, commune, status, created_at
                FROM users ORDER BY created_at DESC LIMIT %s
            """, [limit])
            rows = cur.fetchall()
            users = []
            for r in rows:
                users.append({
                    "id": str(r[0]), "ngd_id": r[1], "first_name": r[2],
                    "last_name": r[3], "phone": r[4], "email": r[5],
                    "profile_type": r[6], "role": r[7], "region": r[8],
                    "commune": r[9], "status": r[10],
                    "created_at": r[11].isoformat() if r[11] else None
                })
            return jsonify(users), 200
    except Exception as e:
        return jsonify({"detail": str(e)}), 500
    finally:
        conn.close()

# ═══════════════════════════════════════════════════════════════════
# ORDERS
# ═══════════════════════════════════════════════════════════════════

@app.route('/api/v1/orders', methods=['GET'])
def list_orders():
    user = getattr(g, 'current_user', None)
    if not user:
        return jsonify({"detail": "Non authentifié."}), 401

    limit = min(200, request.args.get('limit', 100, type=int))
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT o.id, o.order_number, o.total_amount, o.region, o.commune,
                       o.status, o.payment_status, o.created_at,
                       u.id, u.first_name, u.last_name, u.phone
                FROM orders o
                LEFT JOIN users u ON o.user_id = u.id
                ORDER BY o.created_at DESC LIMIT %s
            """, [limit])
            rows = cur.fetchall()
            orders = []
            for r in rows:
                orders.append({
                    "id": str(r[0]), "order_number": r[1], "total_amount": float(r[2]) if r[2] else 0,
                    "region": r[3], "commune": r[4], "status": r[5],
                    "payment_status": r[6], "created_at": r[7].isoformat() if r[7] else None,
                    "user": {
                        "id": str(r[8]) if r[8] else None,
                        "first_name": r[9], "last_name": r[10], "phone": r[11]
                    }
                })
            return jsonify(orders), 200
    except Exception as e:
        return jsonify({"detail": str(e)}), 500
    finally:
        conn.close()

# ═══════════════════════════════════════════════════════════════════
# CAMPAIGNS
# ═══════════════════════════════════════════════════════════════════

def slugify(name):
    base = re.sub(r'[^\w\s-]', '', name.lower()).strip().replace(' ', '-')
    return f"{base[:50]}-{uuid.uuid4().hex[:6]}"

@app.route('/api/v1/campaigns', methods=['GET'])
def list_campaigns():
    user = getattr(g, 'current_user', None)
    if not user:
        return jsonify({"detail": "Non authentifié."}), 401

    page = max(1, request.args.get('page', 1, type=int))
    per_page = min(50, max(1, request.args.get('per_page', 10, type=int)))
    search = request.args.get('search', '')
    status = request.args.get('status', '')
    region = request.args.get('region', '')
    offset = (page - 1) * per_page

    params = []
    conditions = ["1=1"]
    if search:
        conditions.append("(name ILIKE %s OR slug ILIKE %s)")
        params.extend([f"%{search}%", f"%{search}%"])
    if status:
        conditions.append("status = %s")
        params.append(status)
    if region:
        conditions.append("region ILIKE %s")
        params.append(f"%{region}%")

    where_clause = " AND ".join(conditions)
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute(f"SELECT COUNT(*) FROM campaigns WHERE {where_clause}", params)
            total = cur.fetchone()[0]

            cur.execute(f"""
                SELECT id, name, slug, election_type, region, commune,
                       election_date, status, price_ht, price_total,
                       pricing_model, description, created_at, updated_at
                FROM campaigns WHERE {where_clause}
                ORDER BY created_at DESC LIMIT %s OFFSET %s
            """, params + [per_page, offset])
            rows = cur.fetchall()

            campaigns = []
            for r in rows:
                campaigns.append({
                    "id": str(r[0]), "name": r[1], "slug": r[2],
                    "election_type": r[3], "region": r[4], "commune": r[5],
                    "election_date": r[6].isoformat() if r[6] else None,
                    "status": r[7], "price_ht": float(r[8]) if r[8] else 0,
                    "price_total": float(r[9]) if r[9] else 0,
                    "pricing_model": r[10], "description": r[11],
                    "created_at": r[12].isoformat() if r[12] else None,
                    "updated_at": r[13].isoformat() if r[13] else None,
                })

            return jsonify({
                "campaigns": campaigns, "total": total,
                "page": page, "per_page": per_page,
                "total_pages": (total + per_page - 1) // per_page
            }), 200
    except Exception as e:
        return jsonify({"detail": str(e)}), 500
    finally:
        conn.close()

@app.route('/api/v1/campaigns', methods=['POST'])
def create_campaign():
    user = getattr(g, 'current_user', None)
    if not user:
        return jsonify({"detail": "Non authentifié."}), 401
    if user.get('role') not in ['superadmin', 'admin', 'manager']:
        return jsonify({"detail": "Permission insuffisante."}), 403

    data = request.get_json() or {}
    for f in ['name', 'election_type', 'region']:
        if not data.get(f):
            return jsonify({"detail": f"Champ obligatoire: {f}"}), 400

    name = data['name'].strip()
    slug = slugify(name)
    election_type = data['election_type']
    region = data['region'].strip()
    commune = data.get('commune')
    election_date = data.get('election_date') or None
    description = data.get('description')
    price_ht = float(data.get('price_ht', 0))
    pricing_model = data.get('pricing_model', 'forfait')

    tva_rate = 0.18
    price_tva = round(price_ht * tva_rate, 2)
    price_total = round(price_ht + price_tva, 2)

    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO campaigns
                (name, slug, election_type, region, commune, election_date,
                 status, price_ht, price_tva, price_total, pricing_model,
                 description, created_by, created_at)
                VALUES (%s, %s, %s, %s, %s, %s, 'active', %s, %s, %s, %s, %s, %s, NOW())
                RETURNING id
            """, [name, slug, election_type, region, commune, election_date,
                  price_ht, price_tva, price_total, pricing_model, description,
                  user['id']])
            campaign_id = cur.fetchone()[0]
            conn.commit()
            return jsonify({"id": str(campaign_id), "message": "Campagne créée"}), 201
    except Exception as e:
        conn.rollback()
        return jsonify({"detail": str(e)}), 500
    finally:
        conn.close()

@app.route('/api/v1/campaigns/<campaign_id>', methods=['GET'])
def get_campaign(campaign_id):
    user = getattr(g, 'current_user', None)
    if not user:
        return jsonify({"detail": "Non authentifié."}), 401

    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT id, name, slug, election_type, region, commune,
                       election_date, status, price_ht, price_total,
                       pricing_model, description, created_at
                FROM campaigns WHERE id = %s
            """, [campaign_id])
            r = cur.fetchone()
            if not r:
                return jsonify({"detail": "Campagne non trouvée"}), 404
            return jsonify({
                "id": str(r[0]), "name": r[1], "slug": r[2],
                "election_type": r[3], "region": r[4], "commune": r[5],
                "election_date": r[6].isoformat() if r[6] else None,
                "status": r[7], "price_ht": float(r[8]) if r[8] else 0,
                "price_total": float(r[9]) if r[9] else 0,
                "pricing_model": r[10], "description": r[11],
                "created_at": r[12].isoformat() if r[12] else None
            }), 200
    except Exception as e:
        return jsonify({"detail": str(e)}), 500
    finally:
        conn.close()

# ═══════════════════════════════════════════════════════════════════
# DASHBOARD STATS — RÉSILIEN PAR TABLE
# ═══════════════════════════════════════════════════════════════════

@app.route('/api/v1/dashboard/stats', methods=['GET'])
def dashboard_stats():
    user = getattr(g, 'current_user', None)
    if not user:
        return jsonify({"detail": "Non authentifié."}), 401

    conn = get_db()
    stats = {
        "total_users": 0,
        "total_campaigns": 0,
        "total_orders": 0,
        "total_revenue": 0.0,
        "total_groups": 0,
        "pending_withdrawals": 0.0
    }

    try:
        with conn.cursor() as cur:
            # Users
            try:
                cur.execute("SELECT COUNT(*) FROM users WHERE status='active'")
                stats["total_users"] = cur.fetchone()[0]
            except Exception as e:
                app.logger.warning(f"[STATS] users: {e}")

            # Campaigns
            try:
                if table_exists(cur, 'campaigns'):
                    cur.execute("SELECT COUNT(*) FROM campaigns WHERE status='active'")
                    stats["total_campaigns"] = cur.fetchone()[0]
                    cur.execute("SELECT COALESCE(SUM(price_total),0) FROM campaigns WHERE status='active'")
                    stats["total_revenue"] = float(cur.fetchone()[0])
                else:
                    app.logger.warning("[STATS] Table campaigns inexistante")
            except Exception as e:
                app.logger.warning(f"[STATS] campaigns: {e}")

            # Orders
            try:
                if table_exists(cur, 'orders'):
                    cur.execute("SELECT COUNT(*) FROM orders")
                    stats["total_orders"] = cur.fetchone()[0]
                else:
                    app.logger.warning("[STATS] Table orders inexistante")
            except Exception as e:
                app.logger.warning(f"[STATS] orders: {e}")

            # Groups
            try:
                if table_exists(cur, 'groups'):
                    cur.execute("SELECT COUNT(*) FROM groups WHERE status='active'")
                    stats["total_groups"] = cur.fetchone()[0]
            except Exception as e:
                app.logger.warning(f"[STATS] groups: {e}")

            # Withdrawals
            try:
                if table_exists(cur, 'withdrawals'):
                    cur.execute("SELECT COALESCE(SUM(amount),0) FROM withdrawals WHERE status='pending'")
                    stats["pending_withdrawals"] = float(cur.fetchone()[0])
            except Exception as e:
                app.logger.warning(f"[STATS] withdrawals: {e}")

        return jsonify(stats), 200
    except Exception as e:
        app.logger.error(f"[STATS] Global error: {e}")
        return jsonify({"detail": str(e)}), 500
    finally:
        conn.close()

# ═══════════════════════════════════════════════════════════════════
# ERROR HANDLERS
# ═══════════════════════════════════════════════════════════════════

@app.errorhandler(404)
def not_found(e):
    return jsonify({"detail": "Ressource non trouvée."}), 404

@app.errorhandler(500)
def server_error(e):
    return jsonify({"detail": "Erreur interne du serveur."}), 500

# ═══════════════════════════════════════════════════════════════════
# BOOT
# ═══════════════════════════════════════════════════════════════════

if __name__ == '__main__':
    init_db()
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
else:
    init_db()
