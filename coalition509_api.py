"""
Coalition 509 SaaS - Backend Flask
Version: 2.4.1 (Fix db.or_ + N+1 orders + error logging)
"""

import os
import re
import secrets
import traceback
from datetime import datetime, timedelta

from flask import Flask, request, jsonify
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
    s = s.strip('-')
    return s

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
    if u is None:
        return None
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
# DASHBOARD STATS
# ============================================================
@app.route('/api/v1/dashboard/stats', methods=['GET'])
@jwt_required()
def dashboard_stats():
    total_users = User.query.count()
    total_campaigns = Campaign.query.count()
    total_orders = Order.query.count()
    total_groups = Group.query.count()
    pending_withdrawals = Withdrawal.query.filter_by(status='pending').count()
    total_revenue = db.session.query(func.sum(Order.total_amount)).filter_by(payment_status='paid').scalar() or 0
    return jsonify({
        'total_users': total_users,
        'total_campaigns': total_campaigns,
        'total_orders': total_orders,
        'total_groups': total_groups,
        'pending_withdrawals': pending_withdrawals,
        'total_revenue': float(total_revenue)
    })

@app.route('/api/dashboard/stats', methods=['GET'])
@jwt_required()
def dashboard_stats_alias():
    return dashboard_stats()

# ============================================================
# USERS
# ============================================================
@app.route('/api/v1/users', methods=['GET'])
@jwt_required()
def get_users():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
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
@jwt_required()
def get_users_alias():
    return get_users()

# ============================================================
# ORDERS
# ============================================================
@app.route('/api/v1/orders', methods=['GET'])
@jwt_required()
def get_orders():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    q = Order.query.order_by(Order.created_at.desc())
    total = q.count()
    orders = q.offset((page - 1) * per_page).limit(per_page).all()
    # Preload users to avoid N+1
    user_ids = [o.user_id for o in orders if o.user_id]
    users = {u.id: u for u in User.query.filter(User.id.in_(user_ids)).all()} if user_ids else {}
    return jsonify({
        'orders': [order_to_dict(o, user_cache=users) for o in orders],
        'total': total, 'page': page, 'per_page': per_page
    })

@app.route('/api/orders', methods=['GET'])
@jwt_required()
def get_orders_alias():
    return get_orders()

# ============================================================
# CAMPAIGNS
# ============================================================
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
        'total': total, 'page': page, 'per_page': per_page
    })

@app.route('/api/campaigns', methods=['GET'])
@jwt_required()
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

@app.route('/api/v1/campaigns/id', methods=['GET'])
@jwt_required()
def get_campaign():
    campaign_id = request.args.get('id', type=int)
    if not campaign_id:
        return jsonify({'detail': 'Parametre id manquant'}), 400
    c = Campaign.query.get_or_404(campaign_id)
    return jsonify(campaign_to_dict(c))

@app.route('/api/campaigns/id', methods=['GET'])
@jwt_required()
def get_campaign_alias():
    return get_campaign()

@app.route('/api/v1/campaigns/id', methods=['PUT'])
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

@app.route('/api/campaigns/id', methods=['PUT'])
@jwt_required()
def update_campaign_alias():
    return update_campaign()

@app.route('/api/v1/campaigns/id', methods=['DELETE'])
@jwt_required()
def delete_campaign():
    campaign_id = request.args.get('id', type=int)
    if not campaign_id:
        return jsonify({'detail': 'Parametre id manquant'}), 400
    c = Campaign.query.get_or_404(campaign_id)
    db.session.delete(c)
    db.session.commit()
    return jsonify({'detail': 'Campagne supprimee'}), 200

@app.route('/api/campaigns/id', methods=['DELETE'])
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
# HEALTH
# ============================================================
@app.route('/')
def index():
    return jsonify({'status': 'ok', 'version': '2.4.1', 'service': 'Coalition 509 API'})

@app.route('/api/health')
def health():
    return jsonify({'status': 'healthy'})

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

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
