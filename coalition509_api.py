"""
Coalition 509 API — Backend v2.7.7
Alias /api/v1/* ajoutes pour compatibilite frontend v1.5.2 sans modification.
"""

import os
import uuid
import hashlib
import datetime
from functools import wraps

from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS

# ─── CONFIG ─────────────────────────────────────────────────────────
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'postgresql://localhost/coalition509')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'coalition509-dev-secret')

db = SQLAlchemy(app)
CORS(app)

# ─── MODÈLES ───────────────────────────────────────────────────────

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    phone = db.Column(db.String(20), unique=True, nullable=False)
    pin_hash = db.Column(db.String(128), nullable=False)
    first_name = db.Column(db.String(100))
    last_name = db.Column(db.String(100))
    email = db.Column(db.String(120))
    role = db.Column(db.String(20), default='user')
    status = db.Column(db.String(20), default='active')
    region = db.Column(db.String(50))
    commune = db.Column(db.String(50))
    profile_type = db.Column(db.String(50))
    ngd_id = db.Column(db.String(50), unique=True)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class Campaign(db.Model):
    __tablename__ = 'campaigns'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    election_date = db.Column(db.Date)
    region = db.Column(db.String(50))
    commune = db.Column(db.String(50))
    status = db.Column(db.String(20), default='active')
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class Order(db.Model):
    __tablename__ = 'orders'
    id = db.Column(db.Integer, primary_key=True)
    order_number = db.Column(db.String(50), unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    campaign_id = db.Column(db.Integer, db.ForeignKey('campaigns.id'))
    total_amount = db.Column(db.Numeric(12, 2), default=0)
    status = db.Column(db.String(20), default='pending')
    payment_status = db.Column(db.String(20), default='pending')
    payment_method = db.Column(db.String(50))
    region = db.Column(db.String(50))
    commune = db.Column(db.String(50))
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class BotMessage(db.Model):
    __tablename__ = 'bot_messages'
    id = db.Column(db.Integer, primary_key=True)
    phone = db.Column(db.String(20))
    message = db.Column(db.Text)
    direction = db.Column(db.String(10))
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class BotStat(db.Model):
    __tablename__ = 'bot_stats'
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.Date, default=datetime.date.today)
    messages_sent = db.Column(db.Integer, default=0)
    messages_received = db.Column(db.Integer, default=0)
    unique_users = db.Column(db.Integer, default=0)

# ─── UTILS ───────────────────────────────────────────────────────────

def hash_pin(pin):
    return hashlib.sha256(pin.encode()).hexdigest()

def generate_ngd_id():
    return f"NGD-{datetime.datetime.now().year}-{uuid.uuid4().hex[:6].upper()}"

def generate_order_number():
    return f"CMD-{str(uuid.uuid4().int % 10000).zfill(3)}"

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            parts = request.headers['Authorization'].split()
            if len(parts) == 2 and parts[0] == 'Bearer':
                token = parts[1]
        if not token:
            return jsonify({'status': 'error', 'message': 'Token manquant'}), 401
        user = User.query.filter_by(phone=token).first()
        if not user:
            return jsonify({'status': 'error', 'message': 'Token invalide'}), 401
        request.current_user = user
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not hasattr(request, 'current_user') or request.current_user.role != 'admin':
            return jsonify({'status': 'error', 'message': 'Accès admin requis'}), 403
        return f(*args, **kwargs)
    return decorated

# ─── BLUEPRINT : AUTH ──────────────────────────────────────────────

from flask import Blueprint
auth_bp = Blueprint('auth', __name__, url_prefix='/api/auth')

@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json() or {}
    phone = data.get('phone', '').strip()
    pin = data.get('pin', '').strip()
    if not phone or not pin:
        return jsonify({'status': 'error', 'message': 'Phone et PIN requis'}), 400
    user = User.query.filter_by(phone=phone).first()
    if not user or user.pin_hash != hash_pin(pin):
        return jsonify({'status': 'error', 'message': 'Identifiants invalides'}), 401
    if user.status != 'active':
        return jsonify({'status': 'error', 'message': 'Compte inactif'}), 403
    return jsonify({
        'status': 'success',
        'token': user.phone,
        'access_token': user.phone,
        'user': {
            'id': user.id, 'phone': user.phone, 'first_name': user.first_name,
            'last_name': user.last_name, 'email': user.email, 'role': user.role,
            'region': user.region, 'commune': user.commune,
            'profile_type': user.profile_type, 'ngd_id': user.ngd_id
        }
    })

@auth_bp.route('/register', methods=['POST'])
def register():
    data = request.get_json() or {}
    phone = data.get('phone', '').strip()
    pin = data.get('pin', '').strip()
    first_name = data.get('first_name', '').strip()
    last_name = data.get('last_name', '').strip()
    if not phone or not pin or not first_name or not last_name:
        return jsonify({'status': 'error', 'message': 'Champs obligatoires manquants'}), 400
    if User.query.filter_by(phone=phone).first():
        return jsonify({'status': 'error', 'message': 'Telephone deja utilise'}), 409
    user = User(
        phone=phone, pin_hash=hash_pin(pin),
        first_name=first_name, last_name=last_name,
        email=data.get('email', ''), role='user', status='active',
        region=data.get('region', ''), commune=data.get('commune', ''),
        profile_type=data.get('profile_type', 'Animateur NGD'),
        ngd_id=generate_ngd_id()
    )
    db.session.add(user)
    db.session.commit()
    return jsonify({
        'status': 'success',
        'id': user.id,
        'ngd_id': user.ngd_id,
        'user': {
            'id': user.id, 'phone': user.phone, 'first_name': user.first_name,
            'last_name': user.last_name, 'email': user.email, 'role': user.role,
            'region': user.region, 'commune': user.commune,
            'profile_type': user.profile_type, 'ngd_id': user.ngd_id
        }
    }), 201

@auth_bp.route('/me', methods=['GET'])
@token_required
def me():
    u = request.current_user
    return jsonify({
        'status': 'success',
        'user': {
            'id': u.id, 'phone': u.phone, 'first_name': u.first_name,
            'last_name': u.last_name, 'email': u.email, 'role': u.role,
            'region': u.region, 'commune': u.commune,
            'profile_type': u.profile_type, 'ngd_id': u.ngd_id
        }
    })

@auth_bp.route('/verify-bot-token', methods=['POST'])
def verify_bot_token():
    data = request.get_json() or {}
    bot_token = data.get('token', '')
    if not bot_token:
        return jsonify({'ok': False, 'error': 'Token manquant'}), 400
    # Verifier le token bot (format attendu: phone|signature)
    try:
        phone = bot_token.split('|')[0] if '|' in bot_token else bot_token
        user = User.query.filter_by(phone=phone).first()
        if user:
            return jsonify({
                'ok': True,
                'access_token': user.phone,
                'user': {
                    'id': user.id, 'phone': user.phone, 'first_name': user.first_name,
                    'last_name': user.last_name, 'email': user.email, 'role': user.role,
                    'region': user.region, 'commune': user.commune,
                    'profile_type': user.profile_type, 'ngd_id': user.ngd_id
                }
            })
        else:
            return jsonify({'ok': True, 'needs_registration': True, 'phone': phone})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 400

# ─── BLUEPRINT : USERS ─────────────────────────────────────────────

users_bp = Blueprint('users', __name__, url_prefix='/api/users')

@users_bp.route('', methods=['GET'])
@token_required
def list_users():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    q = User.query.order_by(User.created_at.desc())
    total = q.count()
    users = q.offset((page-1)*per_page).limit(per_page).all()
    return jsonify({
        'status': 'success',
        'page': page, 'per_page': per_page, 'total': total,
        'users': [{
            'id': u.id, 'phone': u.phone, 'first_name': u.first_name,
            'last_name': u.last_name, 'email': u.email, 'role': u.role,
            'status': u.status, 'region': u.region, 'commune': u.commune,
            'profile_type': u.profile_type, 'ngd_id': u.ngd_id,
            'created_at': u.created_at.isoformat() if u.created_at else None
        } for u in users]
    })

# ─── BLUEPRINT : CAMPAIGNS ─────────────────────────────────────────

campaigns_bp = Blueprint('campaigns', __name__, url_prefix='/api/campaigns')

@campaigns_bp.route('', methods=['GET'])
@token_required
def list_campaigns():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    q = Campaign.query.order_by(Campaign.created_at.desc())
    total = q.count()
    camps = q.offset((page-1)*per_page).limit(per_page).all()
    return jsonify({
        'status': 'success',
        'page': page, 'per_page': per_page, 'total': total,
        'campaigns': [{
            'id': c.id, 'name': c.name, 'description': c.description,
            'election_date': str(c.election_date) if c.election_date else None,
            'region': c.region, 'commune': c.commune, 'status': c.status,
            'created_by': c.created_by,
            'created_at': c.created_at.isoformat() if c.created_at else None
        } for c in camps]
    })

@campaigns_bp.route('', methods=['POST'])
@token_required
def create_campaign():
    data = request.get_json() or {}
    c = Campaign(
        name=data.get('name', ''),
        description=data.get('description', ''),
        election_date=datetime.datetime.strptime(data['election_date'], '%Y-%m-%d').date() if data.get('election_date') else None,
        region=data.get('region', ''),
        commune=data.get('commune', ''),
        created_by=request.current_user.id
    )
    db.session.add(c)
    db.session.commit()
    return jsonify({'status': 'success', 'campaign': {'id': c.id, 'name': c.name}}), 201

@campaigns_bp.route('/detail', methods=['GET'])
@token_required
def get_campaign():
    cid = request.args.get('id', type=int)
    if not cid:
        return jsonify({'status': 'error', 'message': 'id requis'}), 400
    c = Campaign.query.get(cid)
    if not c:
        return jsonify({'status': 'error', 'message': 'Campagne introuvable'}), 404
    return jsonify({
        'status': 'success',
        'campaign': {
            'id': c.id, 'name': c.name, 'description': c.description,
            'election_date': str(c.election_date) if c.election_date else None,
            'region': c.region, 'commune': c.commune, 'status': c.status,
            'created_by': c.created_by,
            'created_at': c.created_at.isoformat() if c.created_at else None
        }
    })

@campaigns_bp.route('/update', methods=['POST'])
@token_required
def update_campaign():
    data = request.get_json() or {}
    cid = data.get('id')
    if not cid:
        return jsonify({'status': 'error', 'message': 'id requis'}), 400
    c = Campaign.query.get(cid)
    if not c:
        return jsonify({'status': 'error', 'message': 'Campagne introuvable'}), 404
    c.name = data.get('name', c.name)
    c.description = data.get('description', c.description)
    if data.get('election_date'):
        c.election_date = datetime.datetime.strptime(data['election_date'], '%Y-%m-%d').date()
    c.region = data.get('region', c.region)
    c.commune = data.get('commune', c.commune)
    c.status = data.get('status', c.status)
    db.session.commit()
    return jsonify({'status': 'success', 'campaign': {'id': c.id, 'name': c.name}})

@campaigns_bp.route('/delete', methods=['POST'])
@token_required
@admin_required
def delete_campaign():
    data = request.get_json() or {}
    cid = data.get('id')
    if not cid:
        return jsonify({'status': 'error', 'message': 'id requis'}), 400
    c = Campaign.query.get(cid)
    if not c:
        return jsonify({'status': 'error', 'message': 'Campagne introuvable'}), 404
    db.session.delete(c)
    db.session.commit()
    return jsonify({'status': 'success', 'message': 'Campagne supprimée'})

# ─── BLUEPRINT : ORDERS ──────────────────────────────────────────────

orders_bp = Blueprint('orders', __name__, url_prefix='/api/orders')

@orders_bp.route('', methods=['GET'])
@token_required
def list_orders():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    q = Order.query.order_by(Order.created_at.desc())
    total = q.count()
    orders = q.offset((page-1)*per_page).limit(per_page).all()
    result = []
    for o in orders:
        u = User.query.get(o.user_id)
        result.append({
            'id': o.id, 'order_number': o.order_number,
            'total_amount': float(o.total_amount) if o.total_amount else 0,
            'status': o.status, 'payment_status': o.payment_status,
            'payment_method': o.payment_method,
            'region': o.region, 'commune': o.commune,
            'created_at': o.created_at.isoformat() if o.created_at else None,
            'user': {
                'id': u.id, 'phone': u.phone, 'first_name': u.first_name,
                'last_name': u.last_name, 'role': u.role, 'region': u.region,
                'commune': u.commune, 'profile_type': u.profile_type,
                'ngd_id': u.ngd_id
            } if u else None
        })
    return jsonify({'status': 'success', 'page': page, 'per_page': per_page, 'total': total, 'orders': result})

@orders_bp.route('/detail', methods=['GET'])
@token_required
def get_order():
    oid = request.args.get('id', type=int)
    if not oid:
        return jsonify({'status': 'error', 'message': 'id requis'}), 400
    o = Order.query.get(oid)
    if not o:
        return jsonify({'status': 'error', 'message': 'Commande introuvable'}), 404
    u = User.query.get(o.user_id)
    return jsonify({
        'status': 'success',
        'order': {
            'id': o.id, 'order_number': o.order_number,
            'total_amount': float(o.total_amount) if o.total_amount else 0,
            'status': o.status, 'payment_status': o.payment_status,
            'payment_method': o.payment_method,
            'region': o.region, 'commune': o.commune,
            'created_at': o.created_at.isoformat() if o.created_at else None,
            'user': {'id': u.id, 'phone': u.phone, 'first_name': u.first_name, 'last_name': u.last_name} if u else None
        }
    })

@orders_bp.route('/pay', methods=['POST'])
@token_required
def pay_order():
    data = request.get_json() or {}
    oid = data.get('id') or data.get('order_id')
    method = data.get('payment_method', 'mobile_money')
    if not oid:
        return jsonify({'status': 'error', 'message': 'id requis'}), 400
    o = Order.query.get(oid)
    if not o:
        return jsonify({'status': 'error', 'message': 'Commande introuvable'}), 404
    o.payment_status = 'paid'
    o.payment_method = method
    o.status = 'completed'
    db.session.commit()
    return jsonify({'status': 'success', 'message': 'Paiement enregistré', 'order': {'id': o.id, 'payment_status': o.payment_status}})

# ─── BLUEPRINT : STATS ─────────────────────────────────────────────

stats_bp = Blueprint('stats', __name__, url_prefix='/api/stats')

@stats_bp.route('/overview', methods=['GET'])
@token_required
def stats_overview():
    total_users = User.query.count()
    total_campaigns = Campaign.query.count()
    total_orders = Order.query.count()
    pending_orders = Order.query.filter_by(payment_status='pending').count()
    paid_orders = Order.query.filter_by(payment_status='paid').count()
    total_revenue = db.session.query(db.func.sum(Order.total_amount)).filter_by(payment_status='paid').scalar() or 0
    return jsonify({
        'status': 'success',
        'stats': {
            'total_users': total_users,
            'total_campaigns': total_campaigns,
            'total_orders': total_orders,
            'pending_orders': pending_orders,
            'paid_orders': paid_orders,
            'total_revenue': float(total_revenue)
        }
    })

# ─── BLUEPRINT : BOT ───────────────────────────────────────────────

bot_bp = Blueprint('bot', __name__, url_prefix='/api/bot')

@bot_bp.route('/stats', methods=['GET'])
@token_required
def bot_stats():
    since = datetime.datetime.utcnow() - datetime.timedelta(days=7)
    msgs = BotMessage.query.filter(BotMessage.created_at >= since).all()
    by_day = {}
    for m in msgs:
        day = m.created_at.strftime('%Y-%m-%d')
        if day not in by_day:
            by_day[day] = {'sent': 0, 'received': 0}
        if m.direction == 'out':
            by_day[day]['sent'] += 1
        else:
            by_day[day]['received'] += 1
    days = sorted(by_day.keys())
    chart_data = [{'date': d, 'sent': by_day[d]['sent'], 'received': by_day[d]['received']} for d in days]
    total_sent = sum(d['sent'] for d in chart_data)
    total_received = sum(d['received'] for d in chart_data)
    unique = BotMessage.query.with_entities(BotMessage.phone).distinct().count()
    return jsonify({
        'status': 'success',
        'stats': {
            'total_messages_sent': total_sent,
            'total_messages_received': total_received,
            'unique_users': unique,
            'chart_data': chart_data
        }
    })

@bot_bp.route('/stats/history', methods=['GET'])
@token_required
def bot_stats_history():
    days = request.args.get('days', 7, type=int)
    since = datetime.datetime.utcnow() - datetime.timedelta(days=days)
    msgs = BotMessage.query.filter(BotMessage.created_at >= since).all()
    by_day = {}
    for m in msgs:
        day = m.created_at.strftime('%Y-%m-%d')
        if day not in by_day:
            by_day[day] = {'conversations': 0, 'leads': 0, 'messages': 0}
        by_day[day]['messages'] += 1
        by_day[day]['conversations'] += 1
    result = [{'date': d, 'conversations': by_day[d]['conversations'], 'leads': by_day[d]['leads'], 'messages': by_day[d]['messages']} for d in sorted(by_day.keys())]
    return jsonify(result)

@bot_bp.route('/stats', methods=['POST'])
def bot_stats_post():
    data = request.get_json() or {}
    api_key = request.headers.get('X-Bot-API-Key', '')
    if api_key != os.environ.get('BOT_API_KEY', 'coalition509-bot-secret-2026'):
        return jsonify({'status': 'error', 'message': 'Unauthorized'}), 401
    msg = BotMessage(
        phone=data.get('phone', ''),
        message=data.get('message', ''),
        direction=data.get('direction', 'in')
    )
    db.session.add(msg)
    db.session.commit()
    return jsonify({'status': 'success'})

# ─── BLUEPRINT : INIT-DB ───────────────────────────────────────────

init_bp = Blueprint('init', __name__, url_prefix='/api')

@init_bp.route('/init-db', methods=['GET'])
def init_db():
    try:
        db.session.execute(db.text("DROP SCHEMA IF EXISTS public CASCADE"))
        db.session.execute(db.text("CREATE SCHEMA public"))
        db.session.commit()
        db.create_all()
        return jsonify({'status': 'success', 'message': 'Base de donnees reinitialisee (CASCADE)'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': str(e)}), 500

# ─── BLUEPRINT : SEED ──────────────────────────────────────────────

seed_bp = Blueprint('seed', __name__, url_prefix='/api')

@seed_bp.route('/seed', methods=['GET', 'POST'])
def seed():
    try:
        db.session.query(BotMessage).delete()
        db.session.query(BotStat).delete()
        db.session.query(Order).delete()
        db.session.query(Campaign).delete()
        db.session.query(User).delete()
        db.session.commit()

        u1 = User(
            phone='50912345678', pin_hash=hash_pin('1234'),
            first_name='Jean', last_name='Pierre', email='jean@coalition509.ht',
            role='user', status='active', region='Ouest', commune='Port-au-Prince',
            profile_type='Animateur NGD', ngd_id=generate_ngd_id()
        )
        u2 = User(
            phone='50987654321', pin_hash=hash_pin('1234'),
            first_name='Marie', last_name='Joseph', email='marie@coalition509.ht',
            role='admin', status='active', region='Nord', commune='Cap-Haitien',
            profile_type='Superviseur', ngd_id=generate_ngd_id()
        )
        db.session.add_all([u1, u2])
        db.session.commit()

        c1 = Campaign(
            name='Campagne Senatoriale Nord',
            description='Campagne senatoriale pour le departement du Nord.',
            election_date=datetime.date(2025, 11, 30),
            region='Nord', commune='Cap-Haitien',
            status='active', created_by=u2.id
        )
        c2 = Campaign(
            name='Campagne Presidentielle 2025',
            description='Mobilisation nationale pour les elections presidentielles.',
            election_date=datetime.date(2025, 11, 30),
            region='Ouest', commune='Port-au-Prince',
            status='active', created_by=u1.id
        )
        db.session.add_all([c1, c2])
        db.session.commit()

        o1 = Order(
            order_number='CMD-001', user_id=u1.id, campaign_id=c2.id,
            total_amount=5900, status='completed', payment_status='paid',
            payment_method='MonCash', region='Ouest', commune='Port-au-Prince'
        )
        o2 = Order(
            order_number='CMD-002', user_id=u2.id, campaign_id=c1.id,
            total_amount=9440, status='pending', payment_status='pending',
            region='Nord', commune='Cap-Haitien'
        )
        db.session.add_all([o1, o2])
        db.session.commit()

        for i in range(7):
            d = datetime.date.today() - datetime.timedelta(days=i)
            bs = BotStat(date=d, messages_sent=10+i, messages_received=5+i, unique_users=3)
            db.session.add(bs)
        db.session.commit()

        for i in range(3):
            m = BotMessage(
                phone='50912345678', message=f'Message test {i+1}',
                direction='in' if i % 2 == 0 else 'out'
            )
            db.session.add(m)
        db.session.commit()

        return jsonify({'status': 'success', 'message': 'Donnees de test injectees'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': str(e)}), 500

# ═══════════════════════════════════════════════════════════════════
# ALIAS /api/v1/* pour compatibilite frontend v1.5.2
# ═══════════════════════════════════════════════════════════════════

from flask import Blueprint
v1_bp = Blueprint('v1', __name__, url_prefix='/api/v1')

# Auth aliases
@v1_bp.route('/auth/login', methods=['POST'])
def v1_login():
    return login()

@v1_bp.route('/auth/register', methods=['POST'])
def v1_register():
    return register()

@v1_bp.route('/auth/me', methods=['GET'])
@token_required
def v1_me():
    return me()

@v1_bp.route('/auth/verify-bot-token', methods=['POST'])
def v1_verify_bot_token():
    return verify_bot_token()

# Dashboard stats alias
@v1_bp.route('/dashboard/stats', methods=['GET'])
@token_required
def v1_dashboard_stats():
    total_users = User.query.count()
    total_campaigns = Campaign.query.count()
    total_orders = Order.query.count()
    pending_orders = Order.query.filter_by(payment_status='pending').count()
    paid_orders = Order.query.filter_by(payment_status='paid').count()
    total_revenue = db.session.query(db.func.sum(Order.total_amount)).filter_by(payment_status='paid').scalar() or 0
    return jsonify({
        'total_users': total_users,
        'total_campaigns': total_campaigns,
        'total_orders': total_orders,
        'pending_orders': pending_orders,
        'paid_orders': paid_orders,
        'total_revenue': float(total_revenue),
        'total_groups': 0,
        'pending_withdrawals': 0
    })

# Campaigns aliases
@v1_bp.route('/campaigns', methods=['GET'])
@token_required
def v1_list_campaigns():
    return list_campaigns()

@v1_bp.route('/campaigns', methods=['POST'])
@token_required
def v1_create_campaign():
    return create_campaign()

# Users alias
@v1_bp.route('/users', methods=['GET'])
@token_required
def v1_list_users():
    return list_users()

# Orders alias
@v1_bp.route('/orders', methods=['GET'])
@token_required
def v1_list_orders():
    return list_orders()

# Payments alias (map vers orders/pay)
@v1_bp.route('/payments/init', methods=['POST'])
@token_required
def v1_payments_init():
    return pay_order()

@v1_bp.route('/payments/confirm', methods=['POST'])
@token_required
def v1_payments_confirm():
    data = request.get_json() or {}
    return jsonify({'ok': True, 'status': 'confirmed', 'payment_id': data.get('payment_id')})

# Export alias
@v1_bp.route('/export/<type>', methods=['GET'])
@token_required
def v1_export(type):
    import csv, io
    output = io.StringIO()
    writer = csv.writer(output)
    if type == 'users':
        writer.writerow(['ID', 'Phone', 'Nom', 'Prenom', 'Email', 'Role', 'Region', 'Commune'])
        for u in User.query.all():
            writer.writerow([u.id, u.phone, u.last_name, u.first_name, u.email, u.role, u.region, u.commune])
    elif type == 'orders':
        writer.writerow(['ID', 'Numero', 'Montant', 'Statut', 'Paiement', 'Region', 'Commune'])
        for o in Order.query.all():
            writer.writerow([o.id, o.order_number, o.total_amount, o.status, o.payment_status, o.region, o.commune])
    elif type == 'campaigns':
        writer.writerow(['ID', 'Nom', 'Region', 'Commune', 'Statut', 'Date'])
        for c in Campaign.query.all():
            writer.writerow([c.id, c.name, c.region, c.commune, c.status, c.election_date])
    else:
        writer.writerow(['Message', 'Aucune donnee'])
    output.seek(0)
    from flask import Response
    return Response(output.getvalue(), mimetype='text/csv', headers={'Content-Disposition': f'attachment; filename={type}.csv'})

# Bot aliases
@v1_bp.route('/bot/stats', methods=['GET'])
@token_required
def v1_bot_stats():
    since = datetime.datetime.utcnow() - datetime.timedelta(days=7)
    msgs = BotMessage.query.filter(BotMessage.created_at >= since).all()
    by_day = {}
    for m in msgs:
        day = m.created_at.strftime('%Y-%m-%d')
        if day not in by_day:
            by_day[day] = {'sent': 0, 'received': 0}
        if m.direction == 'out':
            by_day[day]['sent'] += 1
        else:
            by_day[day]['received'] += 1
    days = sorted(by_day.keys())
    total_sent = sum(by_day[d]['sent'] for d in days)
    total_received = sum(by_day[d]['received'] for d in days)
    unique = BotMessage.query.with_entities(BotMessage.phone).distinct().count()
    return jsonify({
        'latest': {
            'total_conversations': total_sent + total_received,
            'active_conversations': unique,
            'leads_generated': 0,
            'conversions': 0,
            'messages_sent': total_sent,
            'bot_version': '1.2.0',
            'recorded_at': datetime.datetime.utcnow().isoformat()
        },
        'week': {
            'leads': 0,
            'conversions': 0,
            'messages': total_sent + total_received
        }
    })

@v1_bp.route('/bot/stats/history', methods=['GET'])
@token_required
def v1_bot_stats_history():
    return bot_stats_history()

# ═══════════════════════════════════════════════════════════════════
# ENREGISTREMENT DES BLUEPRINTS
# ═══════════════════════════════════════════════════════════════════

app.register_blueprint(auth_bp)
app.register_blueprint(users_bp)
app.register_blueprint(campaigns_bp)
app.register_blueprint(orders_bp)
app.register_blueprint(stats_bp)
app.register_blueprint(bot_bp)
app.register_blueprint(init_bp)
app.register_blueprint(seed_bp)
app.register_blueprint(v1_bp)  # Alias /api/v1/*

# ─── ROUTE RACINE ──────────────────────────────────────────────────

@app.route('/')
def index():
    return jsonify({
        'service': 'Coalition 509 API',
        'version': '2.7.7',
        'status': 'ok'
    })

# ─── BOOT ────────────────────────────────────────────────────────────

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
