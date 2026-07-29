"""
Coalition 509 SaaS - Backend Flask
Version: 2.7.2 (Fix Orders filtre user + Bot stats latest + Dashboard robuste)
Fichier: coalition509_api.py
"""

import os, re, secrets, traceback, csv, io
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, Response
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import text, or_, func
import bcrypt

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///coalition509.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'dev-secret-change-me')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=7)
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'connect_args': {'sslmode': 'require'},
    'pool_pre_ping': True,
    'pool_recycle': 300
}
CORS(app, resources={r"/api/*": {"origins": "*"}})
db = SQLAlchemy(app)
jwt = JWTManager(app)
BOT_API_KEY = os.environ.get("BOT_API_KEY", "coalition509-bot-secret-2026")

# ============================================================
# MODELS
# ============================================================
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    ngd_id = db.Column(db.String(20), unique=True, nullable=False)
    first_name = db.Column(db.String(100), nullable=False)
    last_name = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=True)
    pin_hash = db.Column(db.String(255), nullable=False)
    profile_type = db.Column(db.String(50), default='Animateur NGD')
    role = db.Column(db.String(50), default='user')
    region = db.Column(db.String(100))
    commune = db.Column(db.String(100))
    status = db.Column(db.String(20), default='active')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class Campaign(db.Model):
    __tablename__ = 'campaigns'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    slug = db.Column(db.String(200), unique=True)
    election_type = db.Column(db.String(50), nullable=False)
    region = db.Column(db.String(100), nullable=False)
    commune = db.Column(db.String(100))
    election_date = db.Column(db.Date)
    description = db.Column(db.Text)
    price_ht = db.Column(db.Numeric(12, 2), default=0)
    price_total = db.Column(db.Numeric(12, 2), default=0)
    pricing_model = db.Column(db.String(20), default='forfait')
    status = db.Column(db.String(20), default='active')
    created_by = db.Column(db.Integer)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class Order(db.Model):
    __tablename__ = 'orders'
    id = db.Column(db.Integer, primary_key=True)
    order_number = db.Column(db.String(50), unique=True)
    user_id = db.Column(db.Integer)
    campaign_id = db.Column(db.Integer)
    total_amount = db.Column(db.Numeric(12, 2), default=0)
    region = db.Column(db.String(100))
    commune = db.Column(db.String(100))
    status = db.Column(db.String(20), default='pending')
    payment_status = db.Column(db.String(20), default='pending')
    payment_method = db.Column(db.String(50))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Group(db.Model):
    __tablename__ = 'groups'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200))
    status = db.Column(db.String(20), default='active')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Withdrawal(db.Model):
    __tablename__ = 'withdrawals'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer)
    amount = db.Column(db.Numeric(12, 2), default=0)
    status = db.Column(db.String(20), default='pending')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class BotToken(db.Model):
    __tablename__ = 'bot_tokens'
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(255), unique=True, nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    used = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime)

class BotStat(db.Model):
    __tablename__ = 'bot_stats'
    id = db.Column(db.Integer, primary_key=True)
    bot_version = db.Column(db.String(20), default='1.2.0')
    total_conversations = db.Column(db.Integer, default=0)
    active_conversations = db.Column(db.Integer, default=0)
    leads_generated = db.Column(db.Integer, default=0)
    conversions = db.Column(db.Integer, default=0)
    messages_sent = db.Column(db.Integer, default=0)
    recorded_at = db.Column(db.DateTime, default=datetime.utcnow)

class Payment(db.Model):
    __tablename__ = 'payments'
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('orders.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    amount = db.Column(db.Numeric(12, 2), default=0)
    currency = db.Column(db.String(10), default='HTG')
    payment_method = db.Column(db.String(50))
    transaction_id = db.Column(db.String(255))
    status = db.Column(db.String(20), default='pending')
    phone = db.Column(db.String(20))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

# ============================================================
# HELPERS
# ============================================================
def generate_ngd_id():
    return f"NGD-{datetime.now().year}-{secrets.token_hex(4).upper()[:6]}"

def hash_pin(pin):
    return generate_password_hash(pin, method='pbkdf2:sha256', salt_length=8)

def verify_pin(pin, hashed):
    if hashed.startswith('$2'):
        return bcrypt.checkpw(pin.encode(), hashed.encode())
    return check_password_hash(hashed, pin)

def make_slug(name):
    s = name.lower()
    s = re.sub(r'[^a-z0-9]+', '-', s)
    return s.strip('-')

def campaign_to_dict(c):
    return {
        'id': c.id, 'name': c.name, 'slug': c.slug,
        'election_type': c.election_type, 'region': c.region, 'commune': c.commune,
        'election_date': c.election_date.isoformat() if c.election_date else None,
        'description': c.description,
        'price_ht': float(c.price_ht) if c.price_ht is not None else 0,
        'price_total': float(c.price_total) if c.price_total is not None else 0,
        'pricing_model': c.pricing_model, 'status': c.status,
        'created_by': c.created_by,
        'created_at': c.created_at.isoformat() if c.created_at else None
    }

def user_to_dict(u):
    if u is None: return None
    return {
        'id': u.id, 'ngd_id': u.ngd_id,
        'first_name': u.first_name, 'last_name': u.last_name,
        'phone': u.phone, 'email': u.email,
        'profile_type': u.profile_type, 'role': u.role,
        'region': u.region, 'commune': u.commune,
        'status': u.status,
        'created_at': u.created_at.isoformat() if u.created_at else None
    }

def order_to_dict(o, user_cache=None):
    user = user_cache.get(o.user_id) if user_cache and o.user_id in user_cache else None
    if user is None and o.user_id:
        user = User.query.get(o.user_id)
    return {
        'id': o.id, 'order_number': o.order_number,
        'user': user_to_dict(user),
        'total_amount': float(o.total_amount) if o.total_amount is not None else 0,
        'region': o.region, 'commune': o.commune,
        'status': o.status, 'payment_status': o.payment_status,
        'payment_method': o.payment_method,
        'created_at': o.created_at.isoformat() if o.created_at else None
    }

# ============================================================
# ERROR HANDLER
# ============================================================
@app.errorhandler(Exception)
def handle_exception(e):
    tb = traceback.format_exc()
    app.logger.error(f"ERROR: {str(e)}\n{tb}")
    return jsonify({'status': 'error', 'message': str(e), 'trace': tb}), 500

# ============================================================
# AUTH
# ============================================================
@app.route('/api/v1/auth/register', methods=['POST'])
def register():
    data = request.get_json() or {}
    required = ['first_name', 'last_name', 'phone', 'pin']
    for f in required:
        if not data.get(f):
            return jsonify({'detail': f'Champ obligatoire: {f}'}), 400
    if not re.match(r'^[0-9]{4}$', str(data['pin'])):
        return jsonify({'detail': 'PIN doit etre 4 chiffres'}), 400
    if User.query.filter_by(phone=data['phone'].strip()).first():
        return jsonify({'detail': 'Telephone deja utilise'}), 409
    user = User(
        ngd_id=generate_ngd_id(),
        first_name=data['first_name'].strip(),
        last_name=data['last_name'].strip(),
        phone=data['phone'].strip().replace(' ', ''),
        email=data.get('email'),
        pin_hash=hash_pin(str(data['pin'])),
        profile_type=data.get('profile_type', 'Animateur NGD'),
        role=data.get('role', 'user'),
        region=data.get('region', ''),
        commune=data.get('commune', '')
    )
    db.session.add(user)
    db.session.commit()
    return jsonify(user_to_dict(user)), 201

@app.route('/api/v1/auth/login', methods=['POST'])
def login():
    data = request.get_json() or {}
    phone = data.get('phone', '').strip().replace(' ', '')
    pin = str(data.get('pin', ''))
    user = User.query.filter_by(phone=phone).first()
    if not user or not verify_pin(pin, user.pin_hash):
        return jsonify({'detail': 'Identifiants incorrects'}), 401
    token = create_access_token(identity=str(user.id))
    return jsonify({'access_token': token, 'user': user_to_dict(user)})

@app.route('/api/v1/auth/me', methods=['GET'])
@jwt_required()
def me():
    user = User.query.get(int(get_jwt_identity()))
    if not user:
        return jsonify({'detail': 'Utilisateur non trouve'}), 404
    return jsonify(user_to_dict(user))

@app.route('/api/v1/auth/me', methods=['PUT'])
@jwt_required()
def update_me():
    user = User.query.get(int(get_jwt_identity()))
    if not user:
        return jsonify({'detail': 'Utilisateur non trouve'}), 404
    data = request.get_json() or {}
    if 'first_name' in data:
        user.first_name = data['first_name'].strip()
    if 'last_name' in data:
        user.last_name = data['last_name'].strip()
    if 'email' in data:
        email = data['email'].strip()
        if email and User.query.filter(User.email == email, User.id != user.id).first():
            return jsonify({'detail': 'Email deja utilise'}), 409
        user.email = email or None
    if 'phone' in data:
        phone = data['phone'].strip().replace(' ', '')
        if phone and User.query.filter(User.phone == phone, User.id != user.id).first():
            return jsonify({'detail': 'Telephone deja utilise'}), 409
        user.phone = phone
    if 'region' in data:
        user.region = data['region'].strip()
    if 'commune' in data:
        user.commune = data['commune'].strip()
    if 'profile_type' in data:
        user.profile_type = data['profile_type']
    if 'pin' in data:
        pin = str(data['pin'])
        if len(pin) == 4 and pin.isdigit():
            user.pin_hash = hash_pin(pin)
    user.updated_at = datetime.utcnow()
    db.session.commit()
    return jsonify(user_to_dict(user))

@app.route('/api/auth/verify-bot-token', methods=['POST'])
def verify_bot_token():
    data = request.get_json() or {}
    token_str = data.get('token', '')
    bt = BotToken.query.filter_by(token=token_str, used=False).first()
    if not bt or (bt.expires_at and bt.expires_at < datetime.utcnow()):
        return jsonify({'ok': False, 'error': 'Token invalide ou expire'}), 400
    user = User.query.filter_by(phone=bt.phone).first()
    if user:
        bt.used = True
        db.session.commit()
        jwt_token = create_access_token(identity=str(user.id))
        return jsonify({'ok': True, 'user': user_to_dict(user), 'access_token': jwt_token})
    return jsonify({'ok': True, 'needs_registration': True, 'phone': bt.phone})

# ============================================================
# BOT
# ============================================================
@app.route('/api/bot/generate-token', methods=['POST'])
def generate_bot_token():
    bot_key = request.headers.get('X-Bot-Key')
    if bot_key != BOT_API_KEY:
        return jsonify({'detail': 'Unauthorized'}), 401
    data = request.get_json() or {}
    phone = data.get('phone', '').strip()
    if not phone:
        return jsonify({'detail': 'Phone required'}), 400
    token = secrets.token_urlsafe(32)
    bt = BotToken(token=token, phone=phone, used=False,
                  expires_at=datetime.utcnow() + timedelta(hours=1))
    db.session.add(bt)
    db.session.commit()
    return jsonify({
        'token': token,
        'expires_at': bt.expires_at.isoformat(),
        'link': f'https://coachmorgans.github.io/coalition509-frontend/dashboard.html?bot_auth={token}'
    })

@app.route('/api/bot/stats', methods=['POST'])
def receive_bot_stats():
    auth_header = request.headers.get('X-Bot-API-Key', '')
    if auth_header != BOT_API_KEY:
        return jsonify({"error": "Unauthorized"}), 401
    data = request.get_json() or {}
    stat = BotStat(
        bot_version=data.get('bot_version', '1.2.0'),
        total_conversations=data.get('total_conversations', 0),
        active_conversations=data.get('active_conversations', 0),
        leads_generated=data.get('leads_generated', 0),
        conversions=data.get('conversions', 0),
        messages_sent=data.get('messages_sent', 0),
        recorded_at=datetime.utcnow()
    )
    db.session.add(stat)
    db.session.commit()
    return jsonify({"status": "ok", "id": stat.id}), 200

@app.route('/api/bot/stats', methods=['GET'])
@jwt_required(optional=True)
def get_bot_stats():
    # Derniere stat SANS limite 24h (evite les 0 si pas de stats aujourd'hui)
    latest = BotStat.query.order_by(BotStat.recorded_at.desc()).first()
    week_ago = datetime.utcnow() - timedelta(days=7)
    week_stats = db.session.query(
        func.sum(BotStat.leads_generated).label('leads'),
        func.sum(BotStat.conversions).label('conversions'),
        func.sum(BotStat.messages_sent).label('messages')
    ).filter(BotStat.recorded_at >= week_ago).first()
    return jsonify({
        "ok": True,
        "latest": {
            "total_conversations": latest.total_conversations if latest else 0,
            "active_conversations": latest.active_conversations if latest else 0,
            "leads_generated": latest.leads_generated if latest else 0,
            "conversions": latest.conversions if latest else 0,
            "messages_sent": latest.messages_sent if latest else 0,
            "recorded_at": latest.recorded_at.isoformat() if latest else None,
            "bot_version": latest.bot_version if latest else None
        },
        "week": {
            "leads": int(week_stats.leads or 0),
            "conversions": int(week_stats.conversions or 0),
            "messages": int(week_stats.messages or 0)
        }
    }), 200

@app.route('/api/bot/stats/history', methods=['GET'])
@jwt_required(optional=True)
def get_bot_stats_history():
    days = int(request.args.get('days', 7))
    since = datetime.utcnow() - timedelta(days=days)
    rows = BotStat.query.filter(BotStat.recorded_at >= since)\
                        .order_by(BotStat.recorded_at.asc()).all()
    return jsonify([{
        "date": r.recorded_at.date().isoformat(),
        "conversations": r.total_conversations,
        "leads": r.leads_generated,
        "messages": r.messages_sent
    } for r in rows]), 200

# ============================================================
# PAIEMENT
# ============================================================
@app.route('/api/v1/payments/init', methods=['POST'])
@jwt_required()
def init_payment():
    data = request.get_json() or {}
    order_id = data.get('order_id')
    method = data.get('method', 'moncash')
    phone = data.get('phone', '')
    if not order_id:
        return jsonify({'detail': 'order_id requis'}), 400
    order = Order.query.get(order_id)
    if not order:
        return jsonify({'detail': 'Commande non trouvee'}), 404
    user_id = int(get_jwt_identity())
    if order.user_id != user_id and not User.query.get(user_id).role in ['admin', 'superadmin']:
        return jsonify({'detail': 'Permission refusee'}), 403
    tx_id = f"TX-{secrets.token_hex(8).upper()}"
    payment = Payment(
        order_id=order_id, user_id=user_id,
        amount=order.total_amount, currency='HTG',
        payment_method=method, transaction_id=tx_id,
        status='pending', phone=phone
    )
    db.session.add(payment)
    db.session.commit()
    instructions = {
        'moncash': f"Envoyez {float(order.total_amount)} Gdes au numero MonCash officiel de Coalition 509. Reference: {tx_id}",
        'natcash': f"Envoyez {float(order.total_amount)} Gdes au numero NatCash officiel. Reference: {tx_id}",
        'paypal': f"Paiement PayPal simule. Reference: {tx_id}",
        'stripe': f"Paiement Stripe simule. Reference: {tx_id}"
    }
    return jsonify({
        'ok': True, 'payment_id': payment.id, 'transaction_id': tx_id,
        'amount': float(order.total_amount), 'method': method,
        'instructions': instructions.get(method, 'Paiement en attente'),
        'status': 'pending'
    })

@app.route('/api/v1/payments/confirm', methods=['POST'])
@jwt_required()
def confirm_payment():
    data = request.get_json() or {}
    payment_id = data.get('payment_id')
    tx_id = data.get('transaction_id')
    payment = Payment.query.filter(
        (Payment.id == payment_id) | (Payment.transaction_id == tx_id)
    ).first()
    if not payment:
        return jsonify({'detail': 'Paiement non trouve'}), 404
    payment.status = 'completed'
    payment.updated_at = datetime.utcnow()
    order = Order.query.get(payment.order_id)
    if order:
        order.payment_status = 'paid'
        order.status = 'completed'
        order.payment_method = payment.payment_method
    db.session.commit()
    return jsonify({
        'ok': True, 'message': 'Paiement confirme',
        'payment': {
            'id': payment.id, 'transaction_id': payment.transaction_id,
            'status': payment.status, 'amount': float(payment.amount)
        }
    })

@app.route('/api/v1/payments', methods=['GET'])
@jwt_required()
def get_payments():
    user_id = int(get_jwt_identity())
    user = User.query.get(user_id)
    q = Payment.query
    if user.role not in ['admin', 'superadmin']:
        q = q.filter_by(user_id=user_id)
    payments = q.order_by(Payment.created_at.desc()).all()
    return jsonify([{
        'id': p.id, 'order_id': p.order_id, 'amount': float(p.amount),
        'currency': p.currency, 'method': p.payment_method,
        'status': p.status, 'transaction_id': p.transaction_id,
        'created_at': p.created_at.isoformat() if p.created_at else None
    } for p in payments])

# ============================================================
# EXPORT CSV
# ============================================================
@app.route('/api/v1/export/campaigns', methods=['GET'])
@jwt_required()
def export_campaigns_csv():
    campaigns = Campaign.query.order_by(Campaign.created_at.desc()).all()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['ID', 'Nom', 'Slug', 'Type', 'Region', 'Commune', 'Date election',
                     'Prix HT', 'Prix Total', 'Modele', 'Statut', 'Cree le'])
    for c in campaigns:
        writer.writerow([
            c.id, c.name, c.slug, c.election_type, c.region, c.commune or '',
            c.election_date.isoformat() if c.election_date else '',
            float(c.price_ht) if c.price_ht else 0,
            float(c.price_total) if c.price_total else 0,
            c.pricing_model, c.status,
            c.created_at.isoformat() if c.created_at else ''
        ])
    output.seek(0)
    return Response(output.getvalue(), mimetype='text/csv',
                    headers={'Content-Disposition': 'attachment; filename=campaigns.csv'})

@app.route('/api/v1/export/orders', methods=['GET'])
@jwt_required()
def export_orders_csv():
    orders = Order.query.order_by(Order.created_at.desc()).all()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['ID', 'Numero', 'Utilisateur', 'Montant', 'Region', 'Commune',
                     'Statut', 'Paiement', 'Methode', 'Cree le'])
    for o in orders:
        user = User.query.get(o.user_id) if o.user_id else None
        writer.writerow([
            o.id, o.order_number or '',
            f"{user.first_name} {user.last_name}" if user else '',
            float(o.total_amount) if o.total_amount else 0,
            o.region or '', o.commune or '',
            o.status, o.payment_status, o.payment_method or '',
            o.created_at.isoformat() if o.created_at else ''
        ])
    output.seek(0)
    return Response(output.getvalue(), mimetype='text/csv',
                    headers={'Content-Disposition': 'attachment; filename=orders.csv'})

@app.route('/api/v1/export/users', methods=['GET'])
@jwt_required()
def export_users_csv():
    user_id = int(get_jwt_identity())
    user = User.query.get(user_id)
    if user.role not in ['admin', 'superadmin']:
        return jsonify({'detail': 'Permission refusee'}), 403
    users = User.query.order_by(User.created_at.desc()).all()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['ID', 'NGD ID', 'Prenom', 'Nom', 'Telephone', 'Email',
                     'Profil', 'Role', 'Region', 'Commune', 'Statut', 'Cree le'])
    for u in users:
        writer.writerow([
            u.id, u.ngd_id, u.first_name, u.last_name, u.phone,
            u.email or '', u.profile_type, u.role,
            u.region or '', u.commune or '', u.status,
            u.created_at.isoformat() if u.created_at else ''
        ])
    output.seek(0)
    return Response(output.getvalue(), mimetype='text/csv',
                    headers={'Content-Disposition': 'attachment; filename=users.csv'})

# ============================================================
# DASHBOARD STATS
# ============================================================
@app.route('/api/v1/dashboard/stats', methods=['GET'])
@jwt_required(optional=True)
def dashboard_stats():
    try:
        total_users = User.query.count()
        total_campaigns = Campaign.query.count()
        total_orders = Order.query.count()
        total_groups = Group.query.count()
        pending_withdrawals = Withdrawal.query.filter_by(status='pending').count()
        total_revenue = db.session.query(func.sum(Order.total_amount)).filter_by(payment_status='paid').scalar()
        total_revenue = float(total_revenue) if total_revenue is not None else 0.0
        return jsonify({
            'total_users': total_users,
            'total_campaigns': total_campaigns,
            'total_orders': total_orders,
            'total_groups': total_groups,
            'pending_withdrawals': pending_withdrawals,
            'total_revenue': total_revenue
        })
    except Exception as e:
        app.logger.error(f"dashboard_stats error: {e}")
        return jsonify({
            'total_users': 0, 'total_campaigns': 0, 'total_orders': 0,
            'total_groups': 0, 'pending_withdrawals': 0, 'total_revenue': 0.0
        }), 200

@app.route('/api/dashboard/stats', methods=['GET'])
@jwt_required(optional=True)
def dashboard_stats_alias():
    return dashboard_stats()

# ============================================================
# USERS
# ============================================================
@app.route('/api/v1/users', methods=['GET'])
@jwt_required(optional=True)
def get_users():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    limit = request.args.get('limit', type=int)
    if limit: per_page = limit
    search = request.args.get('search', '')
    q = User.query
    if search:
        q = q.filter(or_(
            User.first_name.ilike(f'%{search}%'),
            User.last_name.ilike(f'%{search}%'),
            User.phone.ilike(f'%{search}%')
        ))
    total = q.count()
    users = q.order_by(User.created_at.desc()).offset((page - 1) * per_page).limit(per_page).all()
    return jsonify({
        'users': [user_to_dict(u) for u in users],
        'total': total, 'page': page, 'per_page': per_page
    })

@app.route('/api/users', methods=['GET'])
@jwt_required(optional=True)
def get_users_alias():
    return get_users()

# ============================================================
# ORDERS (FILTRE USER SI NON-ADMIN)
# ============================================================
@app.route('/api/v1/orders', methods=['GET'])
@jwt_required(optional=True)
def get_orders():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    limit = request.args.get('limit', type=int)
    if limit: per_page = limit

    # Filtrage par user si connecte et non-admin
    q = Order.query.order_by(Order.created_at.desc())
    try:
        user_id = int(get_jwt_identity())
        user = User.query.get(user_id)
        if user and user.role not in ['admin', 'superadmin']:
            q = q.filter_by(user_id=user_id)
    except:
        pass

    total = q.count()
    orders = q.offset((page - 1) * per_page).limit(per_page).all()
    user_ids = [o.user_id for o in orders if o.user_id]
    users = {u.id: u for u in User.query.filter(User.id.in_(user_ids)).all()} if user_ids else {}
    return jsonify({
        'orders': [order_to_dict(o, user_cache=users) for o in orders],
        'total': total, 'page': page, 'per_page': per_page
    })

@app.route('/api/orders', methods=['GET'])
@jwt_required(optional=True)
def get_orders_alias():
    return get_orders()

# ============================================================
# CAMPAIGNS
# ============================================================
@app.route('/api/v1/campaigns', methods=['GET'])
@jwt_required(optional=True)
def get_campaigns():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    search = request.args.get('search', '')
    status_filter = request.args.get('status', '')
    region_filter = request.args.get('region', '')
    cid = request.args.get('id', type=int)
    if cid:
        c = Campaign.query.get(cid)
        if not c:
            return jsonify({'detail': 'Campagne non trouvee'}), 404
        return jsonify(campaign_to_dict(c))
    q = Campaign.query
    if search:
        q = q.filter(Campaign.name.ilike(f'%{search}%'))
    if status_filter:
        q = q.filter_by(status=status_filter)
    if region_filter:
        q = q.filter(Campaign.region.ilike(f'%{region_filter}%'))
    total = q.count()
    campaigns = q.order_by(Campaign.created_at.desc()).offset((page - 1) * per_page).limit(per_page).all()
    return jsonify({
        'campaigns': [campaign_to_dict(c) for c in campaigns],
        'total': total, 'page': page, 'per_page': per_page
    })

@app.route('/api/campaigns', methods=['GET'])
@jwt_required(optional=True)
def get_campaigns_alias():
    return get_campaigns()

@app.route('/api/v1/campaigns', methods=['POST'])
@jwt_required()
def create_campaign():
    data = request.get_json() or {}
    required = ['name', 'election_type', 'region']
    for f in required:
        if not data.get(f):
            return jsonify({'detail': f'Champ obligatoire: {f}'}), 400
    slug = make_slug(data['name'])
    if Campaign.query.filter_by(slug=slug).first():
        slug = f"{slug}-{secrets.token_hex(2)}"
    price_ht = float(data.get('price_ht', 0))
    price_total = round(price_ht * 1.18, 2)
    campaign = Campaign(
        name=data['name'].strip(), slug=slug,
        election_type=data['election_type'],
        region=data['region'].strip(),
        commune=data.get('commune'),
        election_date=datetime.strptime(data['election_date'], '%Y-%m-%d').date() if data.get('election_date') else None,
        description=data.get('description'),
        price_ht=price_ht, price_total=price_total,
        pricing_model=data.get('pricing_model', 'forfait'),
        status='active', created_by=int(get_jwt_identity())
    )
    db.session.add(campaign)
    db.session.commit()
    return jsonify(campaign_to_dict(campaign)), 201

@app.route('/api/campaigns', methods=['POST'])
@jwt_required()
def create_campaign_alias():
    return create_campaign()

@app.route('/api/v1/campaigns', methods=['PUT'])
@jwt_required()
def update_campaign():
    campaign_id = request.args.get('id', type=int)
    if not campaign_id:
        return jsonify({'detail': 'Parametre id manquant'}), 400
    c = Campaign.query.get_or_404(campaign_id)
    data = request.get_json() or {}
    if 'name' in data:
        c.name = data['name'].strip()
        c.slug = make_slug(c.name)
    if 'election_type' in data:
        c.election_type = data['election_type']
    if 'region' in data:
        c.region = data['region'].strip()
    if 'commune' in data:
        c.commune = data['commune']
    if 'election_date' in data and data['election_date']:
        c.election_date = datetime.strptime(data['election_date'], '%Y-%m-%d').date()
    if 'description' in data:
        c.description = data['description']
    if 'price_ht' in data:
        c.price_ht = float(data['price_ht'])
        c.price_total = round(c.price_ht * 1.18, 2)
    if 'pricing_model' in data:
        c.pricing_model = data['pricing_model']
    if 'status' in data:
        c.status = data['status']
    c.updated_at = datetime.utcnow()
    db.session.commit()
    return jsonify(campaign_to_dict(c))

@app.route('/api/campaigns', methods=['PUT'])
@jwt_required()
def update_campaign_alias():
    return update_campaign()

@app.route('/api/v1/campaigns', methods=['DELETE'])
@jwt_required()
def delete_campaign():
    campaign_id = request.args.get('id', type=int)
    if not campaign_id:
        return jsonify({'detail': 'Parametre id manquant'}), 400
    c = Campaign.query.get_or_404(campaign_id)
    db.session.delete(c)
    db.session.commit()
    return jsonify({'detail': 'Campagne supprimee'}), 200

@app.route('/api/campaigns', methods=['DELETE'])
@jwt_required()
def delete_campaign_alias():
    return delete_campaign()

# ============================================================
# SEED
# ============================================================
@app.route('/api/seed', methods=['GET', 'POST'])
def seed():
    try:
        if not User.query.filter_by(phone='50912345678').first():
            u = User(
                ngd_id=generate_ngd_id(),
                first_name='Jean', last_name='Pierre',
                phone='50912345678', email='jean@coalition509.ht',
                pin_hash=hash_pin('1234'),
                profile_type='Animateur NGD', role='user',
                region='Ouest', commune='Port-au-Prince', status='active'
            )
            db.session.add(u)
        if not User.query.filter_by(phone='50987654321').first():
            u2 = User(
                ngd_id=generate_ngd_id(),
                first_name='Marie', last_name='Joseph',
                phone='50987654321', email='marie@coalition509.ht',
                pin_hash=hash_pin('1234'),
                profile_type='Superviseur', role='admin',
                region='Nord', commune='Cap-Haitien', status='active'
            )
            db.session.add(u2)
        db.session.commit()

        if not Campaign.query.filter_by(slug='municipales-2025-port-au-prince').first():
            c1 = Campaign(
                name='Municipales 2025 - Port-au-Prince',
                slug='municipales-2025-port-au-prince',
                election_type='Municipales',
                region='Ouest', commune='Port-au-Prince',
                election_date=datetime(2025, 12, 15).date(),
                description='Campagne electorale municipale pour la capitale.',
                price_ht=5000.00, price_total=5900.00,
                pricing_model='forfait', status='active', created_by=1
            )
            db.session.add(c1)
        if not Campaign.query.filter_by(slug='senatoriales-2025-nord').first():
            c2 = Campaign(
                name='Senatoriales 2025 - Nord',
                slug='senatoriales-2025-nord',
                election_type='Senatoriales',
                region='Nord', commune='Cap-Haitien',
                election_date=datetime(2025, 11, 30).date(),
                description='Campagne senatoriale pour le departement du Nord.',
                price_ht=8000.00, price_total=9440.00,
                pricing_model='forfait', status='active', created_by=1
            )
            db.session.add(c2)
        db.session.commit()

        if not Order.query.filter_by(order_number='CMD-001').first():
            o1 = Order(
                order_number='CMD-001', user_id=1,
                total_amount=5900.00, region='Ouest', commune='Port-au-Prince',
                status='completed', payment_status='paid'
            )
            db.session.add(o1)
        if not Order.query.filter_by(order_number='CMD-002').first():
            o2 = Order(
                order_number='CMD-002', user_id=2,
                total_amount=9440.00, region='Nord', commune='Cap-Haitien',
                status='pending', payment_status='pending'
            )
            db.session.add(o2)
        db.session.commit()

        if not Group.query.filter_by(name='NGD Port-au-Prince').first():
            db.session.add(Group(name='NGD Port-au-Prince', status='active'))
        if not Group.query.filter_by(name='NGD Cap-Haitien').first():
            db.session.add(Group(name='NGD Cap-Haitien', status='active'))
        db.session.commit()

        return jsonify({'status': 'ok', 'message': 'Donnees de test injectees'})
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Seed error: {str(e)}\n{traceback.format_exc()}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

# ============================================================
# INIT DB
# ============================================================
@app.route('/api/init-db', methods=['GET', 'POST'])
def init_db():
    try:
        db.drop_all()
        db.create_all()
        return jsonify({
            'status': 'ok',
            'message': 'Tables supprimees et recreees. Appelle /api/seed pour injecter les donnees de test.'
        })
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"InitDB error: {str(e)}\n{traceback.format_exc()}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

# ============================================================
# HEALTH
# ============================================================
@app.route('/')
def index():
    return jsonify({'status': 'ok', 'version': '2.7.2', 'service': 'Coalition 509 API'})

@app.route('/api/health')
def health():
    return jsonify({'status': 'healthy'})

# ============================================================
# BOOT
# ============================================================
if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
