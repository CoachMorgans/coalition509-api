# ============================================================
# COALITION 509 SaaS — API Backend v1.1 (Flask)
# Compatible Python 3.14 — Pas de pydantic/rust
# VoteConnect Ecosystem | ChallengeFinancier™
# ============================================================

from flask import Flask, request, jsonify
from functools import wraps
import asyncpg
import bcrypt
import jwt
import os
import json
import asyncio
from datetime import datetime, timezone, timedelta

# ============================================================
# CONFIGURATION
# ============================================================
app = Flask(__name__)
app.config['JSON_SORT_KEYS'] = False

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://postgres:password@db.supabase.co:5432/postgres")
JWT_SECRET = os.getenv("JWT_SECRET", "coalition509-secret-key-change-in-production")
JWT_EXPIRATION_HOURS = 24

# Pool de connexions PostgreSQL — initialisé UNE SEULE FOIS au démarrage
db_pool = None

async def init_db_pool():
    """Initialise le pool de connexions asyncpg."""
    global db_pool
    if db_pool is None:
        db_pool = await asyncpg.create_pool(DATABASE_URL, min_size=2, max_size=10)
        print("✅ Connexion PostgreSQL établie")
    return db_pool

def get_db_pool():
    """Récupère le pool existant (doit être initialisé avant)."""
    if db_pool is None:
        raise RuntimeError("Le pool de base de données n'est pas initialisé. Appelez init_db_pool() d'abord.")
    return db_pool

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

def run_async(coro):
    """Exécute une coroutine async dans un contexte Flask synchrone."""
    try:
        loop = asyncio.get_running_loop()
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor() as executor:
            future = executor.submit(asyncio.run, coro)
            return future.result()
    except RuntimeError:
        return asyncio.run(coro)

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

    async def _register():
        pool = get_db_pool()
        async with pool.acquire() as conn:
            existing = await conn.fetchrow("SELECT id FROM users WHERE phone = $1", phone)
            if existing:
                return jsonify({"detail": "Ce numéro de téléphone est déjà enregistré"}), 400

            pin_hash = hash_pin(pin)
            ngd_id = await conn.fetchval("SELECT generate_ngd_id()")

            row = await conn.fetchrow("""
                INSERT INTO users (phone, first_name, last_name, email, pin_hash, 
                                  profile_type, region, commune, specialty, ngd_id, status)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 'active')
                RETURNING id, phone, first_name, last_name, email, role, profile_type,
                          region, commune, ngd_id, wallet_balance, cashback_balance, status, created_at
            """, phone, first_name, last_name, email, pin_hash, profile_type, region, commune, specialty, ngd_id)

            await conn.execute("""
                SELECT log_activity($1, NULL, 'inscription', 'user', 
                                   $2::jsonb, 'user', $1, 'api')
            """, str(row['id']), json.dumps({"profile_type": profile_type, "region": region}))

            return jsonify(dict(row)), 201

    return run_async(_register())

@app.route('/api/v1/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    phone = data.get('phone', '').strip()
    pin = data.get('pin', '')

    async def _login():
        pool = get_db_pool()
        async with pool.acquire() as conn:
            row = await conn.fetchrow("""
                SELECT id, phone, first_name, last_name, role, pin_hash, status
                FROM users WHERE phone = $1
            """, phone)

            if not row or not verify_pin(pin, row['pin_hash']):
                return jsonify({"detail": "Téléphone ou PIN incorrect"}), 401

            if row['status'] != 'active':
                return jsonify({"detail": "Compte suspendu"}), 403

            await conn.execute("UPDATE users SET last_active = NOW() WHERE id = $1", row['id'])

            token = create_jwt(str(row['id']), row['role'])

            return jsonify({
                "access_token": token,
                "token_type": "bearer",
                "user": {
                    "id": str(row['id']),
                    "phone": row['phone'],
                    "first_name": row['first_name'],
                    "last_name": row['last_name'],
                    "role": row['role']
                }
            })

    return run_async(_login())

@app.route('/api/v1/auth/me', methods=['GET'])
@require_auth
def get_me():
    user_id = request.current_user['sub']

    async def _get_me():
        pool = get_db_pool()
        async with pool.acquire() as conn:
            row = await conn.fetchrow("""
                SELECT id, phone, first_name, last_name, email, role, profile_type,
                       region, commune, ngd_id, wallet_balance, cashback_balance, status, created_at
                FROM users WHERE id = $1
            """, user_id)

            if not row:
                return jsonify({"detail": "Utilisateur non trouvé"}), 404

            return jsonify(dict(row))

    return run_async(_get_me())

# ============================================================
# ROUTES — CAMPAGNES
# ============================================================

@app.route('/api/v1/campaigns', methods=['GET'])
@require_auth
def list_campaigns():
    status = request.args.get('status')
    region = request.args.get('region')

    async def _list():
        pool = get_db_pool()
        async with pool.acquire() as conn:
            query = """
                SELECT id, name, slug, election_type, region, commune, 
                       election_date::text, status, owner_id::text, created_at
                FROM campaigns WHERE 1=1
            """
            params = []

            if status:
                query += f" AND status = ${len(params)+1}"
                params.append(status)
            if region:
                query += f" AND region = ${len(params)+1}"
                params.append(region)

            if request.current_user.get("role") not in ["superadmin", "admin"]:
                query += f" AND (owner_id = ${len(params)+1} OR id IN (SELECT campaign_id FROM team_members WHERE user_id = ${len(params)+1}))"
                params.append(request.current_user['sub'])

            query += " ORDER BY created_at DESC"

            rows = await conn.fetch(query, *params)
            return jsonify([dict(r) for r in rows])

    return run_async(_list())

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

    async def _create():
        pool = get_db_pool()
        async with pool.acquire() as conn:
            slug = name.lower().replace(" ", "-").replace("_", "-")[:100]
            base_slug = slug
            counter = 1
            while await conn.fetchval("SELECT 1 FROM campaigns WHERE slug = $1", slug):
                slug = f"{base_slug}-{counter}"
                counter += 1

            row = await conn.fetchrow("""
                INSERT INTO campaigns (name, slug, election_type, region, commune, 
                                      election_date, owner_id, status, description)
                VALUES ($1, $2, $3, $4, $5, $6, $7, 'active', $8)
                RETURNING id, name, slug, election_type, region, commune, 
                          election_date::text, status, owner_id::text, created_at
            """, name, slug, election_type, region, commune, election_date,
                request.current_user['sub'], description)

            await conn.execute("""
                SELECT log_activity($1, $2, 'creation_campagne', 'campaign',
                                   $3::jsonb, 'campaign', $2, 'api')
            """, request.current_user['sub'], row['id'], json.dumps({"name": name}))

            return jsonify(dict(row)), 201

    return run_async(_create())

@app.route('/api/v1/campaigns/<campaign_id>', methods=['GET'])
@require_auth
def get_campaign(campaign_id):
    async def _get():
        pool = get_db_pool()
        async with pool.acquire() as conn:
            row = await conn.fetchrow("""
                SELECT id, name, slug, election_type, region, commune, 
                       election_date::text, status, owner_id::text, created_at
                FROM campaigns WHERE id = $1
            """, campaign_id)

            if not row:
                return jsonify({"detail": "Campagne non trouvée"}), 404

            return jsonify(dict(row))

    return run_async(_get())

@app.route('/api/v1/campaigns/<campaign_id>/stats', methods=['GET'])
@require_auth
def get_campaign_stats(campaign_id):
    async def _get():
        pool = get_db_pool()
        async with pool.acquire() as conn:
            row = await conn.fetchrow("SELECT * FROM v_campaign_stats WHERE campaign_id = $1", campaign_id)
            if not row:
                return jsonify({"detail": "Campagne non trouvée"}), 404
            return jsonify(dict(row))

    return run_async(_get())

# ============================================================
# ROUTES — GESTION D'ÉQUIPE
# ============================================================

@app.route('/api/v1/campaigns/<campaign_id>/team', methods=['GET'])
@require_auth
def get_team_members(campaign_id):
    async def _get():
        pool = get_db_pool()
        async with pool.acquire() as conn:
            rows = await conn.fetch("""
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
                WHERE tm.campaign_id = $1
                ORDER BY tm.created_at DESC
            """, campaign_id)
            return jsonify([dict(r) for r in rows])

    return run_async(_get())

@app.route('/api/v1/campaigns/<campaign_id>/team/invite', methods=['POST'])
@require_auth
@require_role(["superadmin", "admin", "manager"])
def invite_team_member(campaign_id):
    data = request.get_json()
    user_id = data.get('user_id')
    phone = data.get('phone', '').strip() or None
    role = data.get('role', '')

    async def _invite():
        pool = get_db_pool()
        async with pool.acquire() as conn:
            campaign = await conn.fetchrow("SELECT id FROM campaigns WHERE id = $1", campaign_id)
            if not campaign:
                return jsonify({"detail": "Campagne non trouvée"}), 404

            target_user_id = None
            if user_id:
                user = await conn.fetchrow("SELECT id FROM users WHERE id = $1", user_id)
                if user:
                    target_user_id = user['id']
            elif phone:
                user = await conn.fetchrow("SELECT id FROM users WHERE phone = $1", phone)
                if user:
                    target_user_id = user['id']

            if not target_user_id:
                return jsonify({"detail": "Utilisateur non trouvé. Il doit d'abord s'inscrire."}), 400

            existing = await conn.fetchrow("""
                SELECT id FROM team_members WHERE campaign_id = $1 AND user_id = $2
            """, campaign_id, target_user_id)
            if existing:
                return jsonify({"detail": "Cet utilisateur est déjà membre de l'équipe"}), 400

            row = await conn.fetchrow("""
                INSERT INTO team_members (campaign_id, user_id, role, invited_by, status)
                VALUES ($1, $2, $3, $4, 'pending')
                RETURNING id, campaign_id::text, user_id::text, role, permissions, status, invited_at
            """, campaign_id, target_user_id, role, request.current_user['sub'])

            return jsonify(dict(row)), 201

    return run_async(_invite())

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

    async def _list():
        pool = get_db_pool()
        async with pool.acquire() as conn:
            query = """
                SELECT id, phone, first_name, last_name, email, role, profile_type,
                       region, commune, ngd_id, wallet_balance, cashback_balance, status, created_at
                FROM users WHERE 1=1
            """
            params = []

            if campaign_id:
                query += f" AND id IN (SELECT user_id FROM team_members WHERE campaign_id = ${len(params)+1})"
                params.append(campaign_id)
            if profile_type:
                query += f" AND profile_type = ${len(params)+1}"
                params.append(profile_type)
            if region:
                query += f" AND region = ${len(params)+1}"
                params.append(region)
            if status:
                query += f" AND status = ${len(params)+1}"
                params.append(status)
            if search:
                query += f" AND (first_name ILIKE ${len(params)+1} OR last_name ILIKE ${len(params)+1} OR phone ILIKE ${len(params)+1} OR ngd_id ILIKE ${len(params)+1})"
                params.append(f"%{search}%")

            query += f" ORDER BY created_at DESC LIMIT ${len(params)+1} OFFSET ${len(params)+2}"
            params.extend([limit, offset])

            rows = await conn.fetch(query, *params)
            return jsonify([dict(r) for r in rows])

    return run_async(_list())

@app.route('/api/v1/users/<user_id>/history', methods=['GET'])
@require_auth
def get_user_history(user_id):
    limit = int(request.args.get('limit', 50))

    if request.current_user['sub'] != user_id and request.current_user.get("role") not in ["superadmin", "admin", "manager"]:
        return jsonify({"detail": "Permission insuffisante"}), 403

    async def _get():
        pool = get_db_pool()
        async with pool.acquire() as conn:
            rows = await conn.fetch("""
                SELECT id, action_type, action_category, action_details, source, created_at
                FROM activity_logs
                WHERE user_id = $1
                ORDER BY created_at DESC
                LIMIT $2
            """, user_id, limit)
            return jsonify([dict(r) for r in rows])

    return run_async(_get())

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

    async def _get():
        pool = get_db_pool()
        async with pool.acquire() as conn:
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
                query += f" AND o.campaign_id = ${len(params)+1}"
                params.append(campaign_id)
            if status:
                query += f" AND o.status = ${len(params)+1}"
                params.append(status)
            if payment_status:
                query += f" AND o.payment_status = ${len(params)+1}"
                params.append(payment_status)

            query += f" ORDER BY o.created_at DESC LIMIT ${len(params)+1} OFFSET ${len(params)+2}"
            params.extend([limit, offset])

            rows = await conn.fetch(query, *params)
            return jsonify([dict(r) for r in rows])

    return run_async(_get())

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

    async def _create():
        pool = get_db_pool()
        async with pool.acquire() as conn:
            order_number = await conn.fetchval("SELECT generate_order_number()")

            row = await conn.fetchrow("""
                INSERT INTO tcl_orders (order_number, user_id, items, total_amount,
                                       cashback_community, cashback_colistier, 
                                       delivery_mode, address, region, commune, status)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 'pending')
                RETURNING id, order_number, total_amount, status, payment_status, created_at
            """, order_number, request.current_user['sub'], 
                json.dumps(items), total, cashback_comm, cashback_col,
                delivery_mode, address, region, commune)

            return jsonify(dict(row)), 201

    return run_async(_create())

# ============================================================
# ROUTES — WALLET MI SIKAH
# ============================================================

@app.route('/api/v1/wallet/withdrawals/pending', methods=['GET'])
@require_auth
@require_role(["superadmin", "admin", "agent_croire"])
def get_pending_withdrawals():
    async def _get():
        pool = get_db_pool()
        async with pool.acquire() as conn:
            rows = await conn.fetch("SELECT * FROM v_pending_withdrawals")
            return jsonify([dict(r) for r in rows])

    return run_async(_get())

@app.route('/api/v1/wallet/withdrawals/<tx_id>/validate', methods=['POST'])
@require_auth
@require_role(["superadmin", "admin", "agent_croire"])
def validate_withdrawal(tx_id):
    async def _validate():
        pool = get_db_pool()
        async with pool.acquire() as conn:
            tx = await conn.fetchrow("""
                SELECT user_id, amount FROM wallet_transactions 
                WHERE id = $1 AND type = 'withdrawal' AND withdrawal_status = 'pending'
            """, tx_id)

            if not tx:
                return jsonify({"detail": "Transaction non trouvée ou déjà traitée"}), 404

            await conn.execute("""
                UPDATE users SET wallet_balance = wallet_balance - $1 WHERE id = $2
            """, tx['amount'], tx['user_id'])

            await conn.execute("""
                UPDATE wallet_transactions 
                SET withdrawal_status = 'approved', processed_by = $1, processed_at = NOW()
                WHERE id = $2
            """, request.current_user['sub'], tx_id)

            return jsonify({"message": "Retrait validé"})

    return run_async(_validate())

# ============================================================
# ROUTES — CONFIGURATION
# ============================================================

@app.route('/api/v1/config', methods=['GET'])
@require_auth
def list_configs():
    async def _get():
        pool = get_db_pool()
        async with pool.acquire() as conn:
            rows = await conn.fetch("SELECT config_key, config_value, config_type, description FROM system_config ORDER BY config_key")
            return jsonify([dict(r) for r in rows])

    return run_async(_get())

@app.route('/api/v1/config/<key>', methods=['GET'])
@require_auth
def get_config(key):
    async def _get():
        pool = get_db_pool()
        async with pool.acquire() as conn:
            row = await conn.fetchrow("SELECT config_key, config_value, config_type FROM system_config WHERE config_key = $1", key)
            if not row:
                return jsonify({"detail": "Configuration non trouvée"}), 404
            return jsonify(dict(row))

    return run_async(_get())

# ============================================================
# ROUTES — DASHBOARD & HEALTH
# ============================================================

@app.route('/')
def root():
    return jsonify({
        "name": "Coalition 509 API",
        "version": "1.1.0",
        "status": "operational",
        "ecosystem": "VoteConnect | ChallengeFinancier™",
        "author": "Coach Morgan's (Simplice KOUAME)"
    })

@app.route('/health')
def health():
    db_status = "connected" if db_pool else "disconnected"
    return jsonify({
        "status": "healthy",
        "database": db_status,
        "timestamp": datetime.now(timezone.utc).isoformat()
    })

@app.route('/api/v1/dashboard/stats', methods=['GET'])
@require_auth
def dashboard_stats():
    async def _get():
        pool = get_db_pool()
        async with pool.acquire() as conn:
            stats = await conn.fetchrow("""
                SELECT 
                    (SELECT COUNT(*) FROM users WHERE status = 'active') as total_users,
                    (SELECT COUNT(*) FROM campaigns WHERE status = 'active') as total_campaigns,
                    (SELECT COUNT(*) FROM tcl_orders) as total_orders,
                    (SELECT COALESCE(SUM(total_amount), 0) FROM tcl_orders WHERE payment_status = 'paid') as total_revenue,
                    (SELECT COUNT(*) FROM coalition_groups WHERE status = 'active') as total_groups,
                    (SELECT COUNT(*) FROM lms_enrollments) as total_lms,
                    (SELECT COUNT(*) FROM wallet_transactions WHERE type = 'withdrawal' AND withdrawal_status = 'pending') as pending_withdrawals
            """)
            return jsonify(dict(stats))

    return run_async(_get())

# ============================================================
# DÉMARRAGE — Initialisation du pool au lancement
# ============================================================

if __name__ == '__main__':
    # Initialisation synchrone du pool au démarrage
    asyncio.run(init_db_pool())
    port = int(os.getenv('PORT', 8000))
    app.run(host='0.0.0.0', port=port)
