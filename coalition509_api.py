# ============================================================
# COALITION 509 SaaS — API Backend v2.0 (Flask + psycopg2)
# Compatible Python 3.14 — Synchrone et stable
# VoteConnect Ecosystem | ChallengeFinancier™
# ============================================================

from flask import Flask, request, jsonify
from flask_cors import CORS
from functools import wraps
import psycopg2
import psycopg2.extras
import bcrypt
import jwt
import os
import json
import uuid
from datetime import datetime, timezone, timedelta

# ============================================================
# CONFIGURATION
# ============================================================
app = Flask(__name__)
app.config['JSON_SORT_KEYS'] = False

CORS(app, resources={r'/api/*': {'origins': '*'}}, supports_credentials=True)

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://postgres:password@db.supabase.co:5432/postgres")
JWT_SECRET = os.getenv("JWT_SECRET", "coalition509-secret-key-change-in-production")
JWT_EXPIRATION_HOURS = 24

# Pool de connexions simple
db_pool = None

def get_db():
    """Récupère une connexion à la base de données."""
    global db_pool
    if db_pool is None:
        db_pool = psycopg2.pool.ThreadedConnectionPool(
            minconn=2, maxconn=10, dsn=DATABASE_URL,
            sslmode='require'
        )
        print("✅ Connexion PostgreSQL établie")
    return db_pool.getconn()

def release_db(conn):
    """Libère une connexion."""
    if db_pool:
        db_pool.putconn(conn)

# ============================================================
# HELPERS
# ============================================================

def hash_pin(pin: str) -> str:
    return bcrypt.hashpw(pin.encode(), bcrypt.gensalt()).decode()

def verify_pin(pin: str, hashed: str) -> bool:
    return bcrypt.checkpw(pin.encode(), hashed.encode())

def create_jwt(user_id: str, role: str, campaign_id=None):
    now = datetime.now(timezone.utc)
    payload = {
        "sub": user_id,
        "role": role,
        "campaign_id": campaign_id,
        "exp": now + timedelta(hours=JWT_EXPIRATION_HOURS),
        "iat": now
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")

def decode_jwt(token: str):
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization', '')
        if not auth_header.startswith('Bearer '):
            return jsonify({"detail": "Token manquant"}), 401
        token = auth_header[7:]
        payload = decode_jwt(token)
        if not payload:
            return jsonify({"detail": "Token invalide ou expiré"}), 401
        request.current_user = payload
        return f(*args, **kwargs)
    return decorated

def require_role(allowed_roles):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if not hasattr(request, 'current_user'):
                return jsonify({"detail": "Authentification requise"}), 401
            if request.current_user.get("role") not in allowed_roles:
                return jsonify({"detail": "Permission insuffisante"}), 403
            return f(*args, **kwargs)
        return decorated
    return decorator

def dict_from_row(cursor, row):
    """Convertit une ligne en dictionnaire."""
    if row is None:
        return None
    cols = [desc[0] for desc in cursor.description]
    return dict(zip(cols, row))

def dicts_from_rows(cursor, rows):
    """Convertit plusieurs lignes en liste de dictionnaires."""
    cols = [desc[0] for desc in cursor.description]
    return [dict(zip(cols, row)) for row in rows]

# ============================================================
# ROUTES — AUTHENTIFICATION
# ============================================================

@app.route('/api/v1/auth/register', methods=['POST'])
def register():
    data = request.get_json()
    phone = data.get('phone', '').strip()
    first_name = data.get('first_name', '').strip()
    last_name = data.get('last_name', '').strip()
    email = data.get('email', '').strip() or None
    pin = data.get('pin', '')
    profile_type = data.get('profile_type', 'Animateur NGD')
    region = data.get('region', '').strip() or None
    commune = data.get('commune', '').strip() or None
    specialty = data.get('specialty', '').strip() or None

    if not phone or not first_name or not last_name or not pin:
        return jsonify({"detail": "Champs obligatoires manquants"}), 400

    conn = get_db()
    try:
        with conn.cursor() as cur:
            # Vérifier si le téléphone existe déjà
            cur.execute("SELECT id FROM users WHERE phone = %s", (phone,))
            if cur.fetchone():
                return jsonify({"detail": "Ce numéro de téléphone est déjà enregistré"}), 400

            # Générer NGD ID
            cur.execute("SELECT generate_ngd_id()")
            ngd_id = cur.fetchone()[0]

            pin_hash = hash_pin(pin)

            cur.execute("""
                INSERT INTO users (phone, first_name, last_name, email, pin_hash, 
                                  profile_type, region, commune, specialty, ngd_id, status)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 'active')
                RETURNING id, phone, first_name, last_name, email, role, profile_type,
                          region, commune, ngd_id, wallet_balance, cashback_balance, status, created_at
            """, (phone, first_name, last_name, email, pin_hash, profile_type, region, commune, specialty, ngd_id))

            row = cur.fetchone()
            user = dict_from_row(cur, row)

            # Log activité
            cur.execute("""
                SELECT log_activity(%s, NULL, 'inscription', 'user', 
                                   %s::jsonb, 'user', %s, 'api')
            """, (str(user['id']), json.dumps({"profile_type": profile_type, "region": region}), str(user['id'])))

            conn.commit()
            return jsonify(user), 201
    except Exception as e:
        conn.rollback()
        print(f"❌ Erreur register: {e}")
        return jsonify({"detail": f"Erreur serveur: {str(e)}"}), 500
    finally:
        release_db(conn)

@app.route('/api/v1/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    phone = data.get('phone', '').strip()
    pin = data.get('pin', '')

    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT id, phone, first_name, last_name, role, pin_hash, status
                FROM users WHERE phone = %s
            """, (phone,))

            row = cur.fetchone()
            if not row or not verify_pin(pin, row[5]):
                return jsonify({"detail": "Téléphone ou PIN incorrect"}), 401

            if row[6] != 'active':
                return jsonify({"detail": "Compte suspendu"}), 403

            cur.execute("UPDATE users SET last_active = NOW() WHERE id = %s", (row[0],))
            conn.commit()

            token = create_jwt(str(row[0]), row[4])

            return jsonify({
                "access_token": token,
                "token_type": "bearer",
                "user": {
                    "id": str(row[0]),
                    "phone": row[1],
                    "first_name": row[2],
                    "last_name": row[3],
                    "role": row[4]
                }
            })
    except Exception as e:
        print(f"❌ Erreur login: {e}")
        return jsonify({"detail": f"Erreur serveur: {str(e)}"}), 500
    finally:
        release_db(conn)

@app.route('/api/v1/auth/me', methods=['GET'])
@require_auth
def get_me():
    user_id = request.current_user['sub']

    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT id, phone, first_name, last_name, email, role, profile_type,
                       region, commune, ngd_id, wallet_balance, cashback_balance, status, created_at
                FROM users WHERE id = %s
            """, (user_id,))

            row = cur.fetchone()
            if not row:
                return jsonify({"detail": "Utilisateur non trouvé"}), 404

            return jsonify(dict_from_row(cur, row))
    except Exception as e:
        print(f"❌ Erreur get_me: {e}")
        return jsonify({"detail": f"Erreur serveur: {str(e)}"}), 500
    finally:
        release_db(conn)

# ============================================================
# ROUTES — CAMPAGNES
# ============================================================

@app.route('/api/v1/campaigns', methods=['GET'])
@require_auth
def list_campaigns():
    status = request.args.get('status')
    region = request.args.get('region')

    conn = get_db()
    try:
        with conn.cursor() as cur:
            query = """
                SELECT id, name, slug, election_type, region, commune, 
                       election_date::text, status, owner_id::text, created_at
                FROM campaigns WHERE 1=1
            """
            params = []

            if status:
                query += " AND status = %s"
                params.append(status)
            if region:
                query += " AND region = %s"
                params.append(region)

            if request.current_user.get("role") not in ["superadmin", "admin"]:
                query += " AND (owner_id = %s OR id IN (SELECT campaign_id FROM team_members WHERE user_id = %s))"
                params.extend([request.current_user['sub'], request.current_user['sub']])

            query += " ORDER BY created_at DESC"

            cur.execute(query, params)
            rows = cur.fetchall()
            return jsonify(dicts_from_rows(cur, rows))
    except Exception as e:
        print(f"❌ Erreur list_campaigns: {e}")
        return jsonify({"detail": f"Erreur serveur: {str(e)}"}), 500
    finally:
        release_db(conn)

@app.route('/api/v1/campaigns', methods=['POST'])
@require_auth
@require_role(["superadmin", "admin"])
def create_campaign():
    data = request.get_json()
    name = data.get('name', '').strip()
    election_type = data.get('election_type', '')
    region = data.get('region', '').strip()
    commune = data.get('commune', '').strip() or None
    election_date = data.get('election_date') or None
    description = data.get('description', '').strip() or None

    conn = get_db()
    try:
        with conn.cursor() as cur:
            slug = name.lower().replace(" ", "-").replace("_", "-")[:100]
            base_slug = slug
            counter = 1
            cur.execute("SELECT 1 FROM campaigns WHERE slug = %s", (slug,))
            while cur.fetchone():
                slug = f"{base_slug}-{counter}"
                counter += 1
                cur.execute("SELECT 1 FROM campaigns WHERE slug = %s", (slug,))

            cur.execute("""
                INSERT INTO campaigns (name, slug, election_type, region, commune, 
                                      election_date, owner_id, status, description)
                VALUES (%s, %s, %s, %s, %s, %s, %s, 'active', %s)
                RETURNING id, name, slug, election_type, region, commune, 
                          election_date::text, status, owner_id::text, created_at
            """, (name, slug, election_type, region, commune, election_date,
                  request.current_user['sub'], description))

            row = cur.fetchone()
            campaign = dict_from_row(cur, row)

            cur.execute("""
                SELECT log_activity(%s, %s, 'creation_campagne', 'campaign',
                                   %s::jsonb, 'campaign', %s, 'api')
            """, (request.current_user['sub'], campaign['id'], json.dumps({"name": name}), campaign['id']))

            conn.commit()
            return jsonify(campaign), 201
    except Exception as e:
        conn.rollback()
        print(f"❌ Erreur create_campaign: {e}")
        return jsonify({"detail": f"Erreur serveur: {str(e)}"}), 500
    finally:
        release_db(conn)

@app.route('/api/v1/campaigns/<campaign_id>', methods=['GET'])
@require_auth
def get_campaign(campaign_id):
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT id, name, slug, election_type, region, commune, 
                       election_date::text, status, owner_id::text, created_at
                FROM campaigns WHERE id = %s
            """, (campaign_id,))

            row = cur.fetchone()
            if not row:
                return jsonify({"detail": "Campagne non trouvée"}), 404

            return jsonify(dict_from_row(cur, row))
    except Exception as e:
        print(f"❌ Erreur get_campaign: {e}")
        return jsonify({"detail": f"Erreur serveur: {str(e)}"}), 500
    finally:
        release_db(conn)

@app.route('/api/v1/campaigns/<campaign_id>/stats', methods=['GET'])
@require_auth
def get_campaign_stats(campaign_id):
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM v_campaign_stats WHERE campaign_id = %s", (campaign_id,))
            row = cur.fetchone()
            if not row:
                return jsonify({"detail": "Campagne non trouvée"}), 404
            return jsonify(dict_from_row(cur, row))
    except Exception as e:
        print(f"❌ Erreur get_campaign_stats: {e}")
        return jsonify({"detail": f"Erreur serveur: {str(e)}"}), 500
    finally:
        release_db(conn)

# ============================================================
# ROUTES — GESTION D'ÉQUIPE
# ============================================================

@app.route('/api/v1/campaigns/<campaign_id>/team', methods=['GET'])
@require_auth
def get_team_members(campaign_id):
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT tm.id, tm.campaign_id::text, tm.user_id::text, tm.role, tm.permissions,
                       tm.status, tm.invited_at, tm.accepted_at,
                       json_build_object(
                           'first_name', u.first_name,
                           'last_name', u.last_name,
                           'phone', u.phone,
                           'email', u.email,
                           'profile_type', u.profile_type
                       ) as user
                FROM team_members tm
                JOIN users u ON tm.user_id = u.id
                WHERE tm.campaign_id = %s
                ORDER BY tm.created_at DESC
            """, (campaign_id,))
            rows = cur.fetchall()
            return jsonify(dicts_from_rows(cur, rows))
    except Exception as e:
        print(f"❌ Erreur get_team_members: {e}")
        return jsonify({"detail": f"Erreur serveur: {str(e)}"}), 500
    finally:
        release_db(conn)

@app.route('/api/v1/campaigns/<campaign_id>/team/invite', methods=['POST'])
@require_auth
@require_role(["superadmin", "admin", "manager"])
def invite_team_member(campaign_id):
    data = request.get_json()
    user_id = data.get('user_id')
    phone = data.get('phone', '').strip() or None
    role = data.get('role', '')

    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM campaigns WHERE id = %s", (campaign_id,))
            if not cur.fetchone():
                return jsonify({"detail": "Campagne non trouvée"}), 404

            target_user_id = None
            if user_id:
                cur.execute("SELECT id FROM users WHERE id = %s", (user_id,))
                row = cur.fetchone()
                if row:
                    target_user_id = row[0]
            elif phone:
                cur.execute("SELECT id FROM users WHERE phone = %s", (phone,))
                row = cur.fetchone()
                if row:
                    target_user_id = row[0]

            if not target_user_id:
                return jsonify({"detail": "Utilisateur non trouvé. Il doit d'abord s'inscrire."}), 400

            cur.execute("""
                SELECT id FROM team_members WHERE campaign_id = %s AND user_id = %s
            """, (campaign_id, target_user_id))
            if cur.fetchone():
                return jsonify({"detail": "Cet utilisateur est déjà membre de l'équipe"}), 400

            cur.execute("""
                INSERT INTO team_members (campaign_id, user_id, role, invited_by, status)
                VALUES (%s, %s, %s, %s, 'pending')
                RETURNING id, campaign_id::text, user_id::text, role, permissions, status, invited_at
            """, (campaign_id, target_user_id, role, request.current_user['sub']))

            row = cur.fetchone()
            conn.commit()
            return jsonify(dict_from_row(cur, row)), 201
    except Exception as e:
        conn.rollback()
        print(f"❌ Erreur invite_team_member: {e}")
        return jsonify({"detail": f"Erreur serveur: {str(e)}"}), 500
    finally:
        release_db(conn)

# ============================================================
# ROUTES — UTILISATEURS
# ============================================================

@app.route('/api/v1/users', methods=['GET'])
@require_auth
def list_users():
    campaign_id = request.args.get('campaign_id')
    profile_type = request.args.get('profile_type')
    region = request.args.get('region')
    status = request.args.get('status')
    search = request.args.get('search', '')
    limit = int(request.args.get('limit', 50))
    offset = int(request.args.get('offset', 0))

    conn = get_db()
    try:
        with conn.cursor() as cur:
            query = """
                SELECT id, phone, first_name, last_name, email, role, profile_type,
                       region, commune, ngd_id, wallet_balance, cashback_balance, status, created_at
                FROM users WHERE 1=1
            """
            params = []

            if campaign_id:
                query += " AND id IN (SELECT user_id FROM team_members WHERE campaign_id = %s)"
                params.append(campaign_id)
            if profile_type:
                query += " AND profile_type = %s"
                params.append(profile_type)
            if region:
                query += " AND region = %s"
                params.append(region)
            if status:
                query += " AND status = %s"
                params.append(status)
            if search:
                query += " AND (first_name ILIKE %s OR last_name ILIKE %s OR phone ILIKE %s OR ngd_id ILIKE %s)"
                params.extend([f"%{search}%"] * 4)

            query += " ORDER BY created_at DESC LIMIT %s OFFSET %s"
            params.extend([limit, offset])

            cur.execute(query, params)
            rows = cur.fetchall()
            return jsonify(dicts_from_rows(cur, rows))
    except Exception as e:
        print(f"❌ Erreur list_users: {e}")
        return jsonify({"detail": f"Erreur serveur: {str(e)}"}), 500
    finally:
        release_db(conn)

@app.route('/api/v1/users/<user_id>/history', methods=['GET'])
@require_auth
def get_user_history(user_id):
    limit = int(request.args.get('limit', 50))

    if request.current_user['sub'] != user_id and request.current_user.get("role") not in ["superadmin", "admin", "manager"]:
        return jsonify({"detail": "Permission insuffisante"}), 403

    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT id, action_type, action_category, action_details, source, created_at
                FROM activity_logs
                WHERE user_id = %s
                ORDER BY created_at DESC
                LIMIT %s
            """, (user_id, limit))
            rows = cur.fetchall()
            return jsonify(dicts_from_rows(cur, rows))
    except Exception as e:
        print(f"❌ Erreur get_user_history: {e}")
        return jsonify({"detail": f"Erreur serveur: {str(e)}"}), 500
    finally:
        release_db(conn)

# ============================================================
# ROUTES — COMMANDES TCL
# ============================================================

@app.route('/api/v1/orders', methods=['GET'])
@require_auth
def get_orders():
    campaign_id = request.args.get('campaign_id')
    status = request.args.get('status')
    payment_status = request.args.get('payment_status')
    limit = int(request.args.get('limit', 50))
    offset = int(request.args.get('offset', 0))

    conn = get_db()
    try:
        with conn.cursor() as cur:
            query = """
                SELECT o.id, o.order_number, o.total_amount, o.status, o.payment_status,
                       o.created_at, o.region, o.commune,
                       json_build_object('first_name', u.first_name, 'last_name', u.last_name, 'phone', u.phone) as user
                FROM tcl_orders o
                JOIN users u ON o.user_id = u.id
                WHERE 1=1
            """
            params = []

            if campaign_id:
                query += " AND o.campaign_id = %s"
                params.append(campaign_id)
            if status:
                query += " AND o.status = %s"
                params.append(status)
            if payment_status:
                query += " AND o.payment_status = %s"
                params.append(payment_status)

            query += " ORDER BY o.created_at DESC LIMIT %s OFFSET %s"
            params.extend([limit, offset])

            cur.execute(query, params)
            rows = cur.fetchall()
            return jsonify(dicts_from_rows(cur, rows))
    except Exception as e:
        print(f"❌ Erreur get_orders: {e}")
        return jsonify({"detail": f"Erreur serveur: {str(e)}"}), 500
    finally:
        release_db(conn)

@app.route('/api/v1/orders', methods=['POST'])
@require_auth
def create_order():
    data = request.get_json()
    items = data.get('items', [])
    delivery_mode = data.get('delivery_mode', '')
    address = data.get('address', '').strip() or None
    region = data.get('region', '').strip() or None
    commune = data.get('commune', '').strip() or None

    total = sum(item.get("montant", 0) * item.get("qte", 1) for item in items)
    cashback_comm = round(total * 0.025) if total >= 30000 else 0
    cashback_col = round(total * 0.01) if total >= 30000 else 0

    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT generate_order_number()")
            order_number = cur.fetchone()[0]

            cur.execute("""
                INSERT INTO tcl_orders (order_number, user_id, items, total_amount,
                                       cashback_community, cashback_colistier, 
                                       delivery_mode, address, region, commune, status)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 'pending')
                RETURNING id, order_number, total_amount, status, payment_status, created_at
            """, (order_number, request.current_user['sub'], 
                  json.dumps(items), total, cashback_comm, cashback_col,
                  delivery_mode, address, region, commune))

            row = cur.fetchone()
            conn.commit()
            return jsonify(dict_from_row(cur, row)), 201
    except Exception as e:
        conn.rollback()
        print(f"❌ Erreur create_order: {e}")
        return jsonify({"detail": f"Erreur serveur: {str(e)}"}), 500
    finally:
        release_db(conn)

# ============================================================
# ROUTES — WALLET MI SIKAH
# ============================================================

@app.route('/api/v1/wallet/withdrawals/pending', methods=['GET'])
@require_auth
@require_role(["superadmin", "admin", "agent_croire"])
def get_pending_withdrawals():
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM v_pending_withdrawals")
            rows = cur.fetchall()
            return jsonify(dicts_from_rows(cur, rows))
    except Exception as e:
        print(f"❌ Erreur get_pending_withdrawals: {e}")
        return jsonify({"detail": f"Erreur serveur: {str(e)}"}), 500
    finally:
        release_db(conn)

@app.route('/api/v1/wallet/withdrawals/<tx_id>/validate', methods=['POST'])
@require_auth
@require_role(["superadmin", "admin", "agent_croire"])
def validate_withdrawal(tx_id):
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT user_id, amount FROM wallet_transactions 
                WHERE id = %s AND type = 'withdrawal' AND withdrawal_status = 'pending'
            """, (tx_id,))

            row = cur.fetchone()
            if not row:
                return jsonify({"detail": "Transaction non trouvée ou déjà traitée"}), 404

            cur.execute("""
                UPDATE users SET wallet_balance = wallet_balance - %s WHERE id = %s
            """, (row[1], row[0]))

            cur.execute("""
                UPDATE wallet_transactions 
                SET withdrawal_status = 'approved', processed_by = %s, processed_at = NOW()
                WHERE id = %s
            """, (request.current_user['sub'], tx_id))

            conn.commit()
            return jsonify({"message": "Retrait validé"})
    except Exception as e:
        conn.rollback()
        print(f"❌ Erreur validate_withdrawal: {e}")
        return jsonify({"detail": f"Erreur serveur: {str(e)}"}), 500
    finally:
        release_db(conn)

# ============================================================
# ROUTES — CONFIGURATION
# ============================================================

@app.route('/api/v1/config', methods=['GET'])
@require_auth
def list_configs():
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT config_key, config_value, config_type, description FROM system_config ORDER BY config_key")
            rows = cur.fetchall()
            return jsonify(dicts_from_rows(cur, rows))
    except Exception as e:
        print(f"❌ Erreur list_configs: {e}")
        return jsonify({"detail": f"Erreur serveur: {str(e)}"}), 500
    finally:
        release_db(conn)

@app.route('/api/v1/config/<key>', methods=['GET'])
@require_auth
def get_config(key):
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT config_key, config_value, config_type FROM system_config WHERE config_key = %s", (key,))
            row = cur.fetchone()
            if not row:
                return jsonify({"detail": "Configuration non trouvée"}), 404
            return jsonify(dict_from_row(cur, row))
    except Exception as e:
        print(f"❌ Erreur get_config: {e}")
        return jsonify({"detail": f"Erreur serveur: {str(e)}"}), 500
    finally:
        release_db(conn)

# ============================================================
# ROUTES — DASHBOARD & HEALTH
# ============================================================

@app.route('/')
def root():
    return jsonify({
        "name": "Coalition 509 API",
        "version": "2.0.0",
        "status": "operational",
        "ecosystem": "VoteConnect | ChallengeFinancier™",
        "author": "Coach Morgan's (Simplice KOUAME)"
    })

@app.route('/health')
def health():
    try:
        conn = get_db()
        with conn.cursor() as cur:
            cur.execute("SELECT 1")
            cur.fetchone()
        release_db(conn)
        db_status = "connected"
    except Exception as e:
        db_status = f"error: {str(e)}"
    return jsonify({
        "status": "healthy",
        "database": db_status,
        "timestamp": datetime.now(timezone.utc).isoformat()
    })

@app.route('/api/v1/dashboard/stats', methods=['GET'])
@require_auth
def dashboard_stats():
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT 
                    (SELECT COUNT(*) FROM users WHERE status = 'active') as total_users,
                    (SELECT COUNT(*) FROM campaigns WHERE status = 'active') as total_campaigns,
                    (SELECT COUNT(*) FROM tcl_orders) as total_orders,
                    (SELECT COALESCE(SUM(total_amount), 0) FROM tcl_orders WHERE payment_status = 'paid') as total_revenue,
                    (SELECT COUNT(*) FROM coalition_groups WHERE status = 'active') as total_groups,
                    (SELECT COUNT(*) FROM lms_enrollments) as total_lms,
                    (SELECT COUNT(*) FROM wallet_transactions WHERE type = 'withdrawal' AND withdrawal_status = 'pending') as pending_withdrawals
            """)
            row = cur.fetchone()
            return jsonify(dict_from_row(cur, row))
    except Exception as e:
        print(f"❌ Erreur dashboard_stats: {e}")
        return jsonify({"detail": f"Erreur serveur: {str(e)}"}), 500
    finally:
        release_db(conn)

# ============================================================
# DÉMARRAGE
# ============================================================

if __name__ == '__main__':
    port = int(os.getenv('PORT', 8000))
    app.run(host='0.0.0.0', port=port)
