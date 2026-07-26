"""
Coalition 509 SaaS — Backend Flask
Version: 2.3.4 (Fix route campaigns + tarification + pagination)
"""

import os
import re
import uuid
import secrets
from datetime import datetime, timedelta
from functools import wraps

from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import bcrypt

# ── CONFIG ──
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///coalition509.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'dev-secret-change-me')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=7)

CORS(app, resources={r"/api/*": {"origins": "*"}})
db = SQLAlchemy(app)
jwt = JWTManager(app)

# ── MODÈLES ──
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
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class Order(db.Model):
    __tablename__ = 'orders'
    id = db.Column(db.Integer, primary_key=True)
    order_number = db.Column(db.String(50), unique=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    total_amount = db.Column(db.Numeric(12, 2), default=0)
    region = db.Column(db.String(100))
    commune = db.Column(db.String(100))
    status = db.Column(db.String(20), default='pending')
    payment_status = db.Column(db.String(20), default='pending')
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
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
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

# ── HELPERS ──
def generate_ngd_id():
    return f"NGD-{datetime.now().year}-{secrets.token_hex(4).upper()[:6]}"

def hash_pin(pin):
    return generate_password_hash(pin, method='pbkdf2:sha256', salt_length=8)

def verify_pin(pin, hashed):
    if hashed.startswith('$2'):
        return bcrypt.checkpw(pin.encode(), hashed.encode())
    return check_password_hash(hashed, pin)

def campaign_to_dict(c):
    return {
        'id': c.id,
        'name': c.name,
        'slug': c.slug,
        'election_type': c.election_type,
        'region': c.region,
        'commune': c.commune,
        'election_date': c.election_date.isoformat() if c.election_date else None,
        'description': c.description,
        'price_ht': float(c.price_ht) if c.price_ht else 0,
        'price_total': float(c.price_total) if c.price_total else 0,
        'pricing_model': c.pricing_model,
        'status': c.status,
        'created_by': c.created_by,
        'created_at': c.created_at.isoformat() if c.created_at else None
    }

def user_to_dict(u):
    return {
        'id': u.id,
        'ngd_id': u.ngd_id,
        'first_name': u.first_name,
        'last_name': u.last_name,
        'phone': u.phone,
        'email': u.email,
        'profile_type': u.profile_type,
        'role': u.role,
        'region': u.region,
        'commune': u.commune,
        'status': u.status,
        'created_at': u.created_at.isoformat() if u.created_at else None
    }

def order_to_dict(o):
    user = User.query.get(o.user_id) if o.user_id else None
    return {
        'id': o.id,
        'order_number': o.order_number,
        'user': user_to_dict(user) if user else None,
        'total_amount': float(o.total_amount) if o.total_amount else 0,
        'region': o.region,
        'commune': o.commune,
        'status': o.status,
        'payment_status': o.payment_status,
        'created_at': o.created_at.isoformat() if o.created_at else None
    }

# ── AUTH ──
@app.route('/api/v1/auth/register', methods=['POST'])
def register():
    data = request.get_json() or {}
    required = ['first_name', 'last_name', 'phone', 'pin']
    for f in required:
        if not data.get(f):
            return jsonify({'detail': f'Champ obligatoire: {f}'}), 400
    if not re.match(r'^\d{4}$', str(data['pin'])):
        return jsonify({'detail': 'PIN doit être 4 chiffres'}), 400
    if User.query.filter_by(phone=data['phone'].strip()).first():
        return jsonify({'detail': 'Téléphone déjà utilisé'}), 409

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
        return jsonify({'detail': 'Utilisateur non trouvé'}), 404
    return jsonify(user_to_dict(user))

@app.route('/api/auth/verify-bot-token', methods=['POST'])
def verify_bot_token():
    data = request.get_json() or {}
    token_str = data.get('token', '')
    bt = BotToken.query.filter_by(token=token_str, used=False).first()
    if not bt or (bt.expires_at and bt.expires_at < datetime.utcnow()):
        return jsonify({'ok': False, 'error': 'Token invalide ou expiré'}), 400
    user = User.query.filter_by(phone=bt.phone).first()
    if user:
        bt.used = True
        db.session.commit()
        jwt_token = create_access_token(identity=str(user.id))
        return jsonify({'ok': True, 'user': user_to_dict(user), 'access_token': jwt_token})
    return jsonify({'ok': True, 'needs_registration': True, 'phone': bt.phone})

# ── DASHBOARD STATS ──
@app.route('/api/v1/dashboard/stats', methods=['GET'])
@jwt_required()
def dashboard_stats():
    total_users = User.query.count()
    total_campaigns = Campaign.query.count()
    total_orders = Order.query.count()
    total_groups = Group.query.count()
    pending_withdrawals = Withdrawal.query.filter_by(status='pending').count()
    total_revenue = db.session.query(db.func.sum(Order.total_amount)).filter_by(payment_status='paid').scalar() or 0
    return jsonify({
        'total_users': total_users,
        'total_campaigns': total_campaigns,
        'total_orders': total_orders,
        'total_groups': total_groups,
        'pending_withdrawals': pending_withdrawals,
        'total_revenue': float(total_revenue)
    })

# ── USERS ──
@app.route('/api/v1/users', methods=['GET'])
@jwt_required()
def get_users():
    limit = request.args.get('limit', 100, type=int)
    users = User.query.order_by(User.created_at.desc()).limit(limit).all()
    return jsonify([user_to_dict(u) for u in users])

# ── ORDERS ──
@app.route('/api/v1/orders', methods=['GET'])
@jwt_required()
def get_orders():
    limit = request.args.get('limit', 100, type=int)
    orders = Order.query.order_by(Order.created_at.desc()).limit(limit).all()
    return jsonify([order_to_dict(o) for o in orders])

# ── CAMPAGNES (FIX v2.3.4) ──
@app.route('/api/v1/campaigns', methods=['GET'])
@jwt_required()
def get_campaigns():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    search = request.args.get('search', '')
    status_filter = request.args.get('status', '')
    region_filter = request.args.get('region', '')

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
        'total': total,
        'page': page,
        'per_page': per_page
    })

@app.route('/api/v1/campaigns', methods=['POST'])
@jwt_required()
def create_campaign():
    data = request.get_json() or {}
    required = ['name', 'election_type', 'region']
    for f in required:
        if not data.get(f):
            return jsonify({'detail': f'Champ obligatoire: {f}'}), 400

    slug = re.sub(r'[^\w]+', '-', data['name'].lower()).strip('-')
    existing = Campaign.query.filter_by(slug=slug).first()
    if existing:
        slug = f"{slug}-{secrets.token_hex(2)}"

    price_ht = float(data.get('price_ht', 0))
    tva = 0.18  # TVA 18%
    price_total = round(price_ht * (1 + tva), 2)

    user_id = int(get_jwt_identity())
    campaign = Campaign(
        name=data['name'].strip(),
        slug=slug,
        election_type=data['election_type'],
        region=data['region'].strip(),
        commune=data.get('commune'),
        election_date=datetime.strptime(data['election_date'], '%Y-%m-%d').date() if data.get('election_date') else None,
        description=data.get('description'),
        price_ht=price_ht,
        price_total=price_total,
        pricing_model=data.get('pricing_model', 'forfait'),
        status='active',
        created_by=user_id
    )
    db.session.add(campaign)
    db.session.commit()
    return jsonify(campaign_to_dict(campaign)), 201

# ── HEALTH ──
@app.route('/')
def index():
    return jsonify({'status': 'ok', 'version': '2.3.4', 'service': 'Coalition 509 API'})

@app.route('/api/health')
def health():
    return jsonify({'status': 'healthy'})

# ── INIT DB ──
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
