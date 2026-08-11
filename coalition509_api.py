"""
Coalition 509 API — Backend v2.9.5
Module SHOP intégré : Produits, Panier, Commandes, Fournisseurs, Livraisons, Paiements, Factures, Stocks
Fix : teardown session + rollback stats + SSL EOF robustness
RÈGLE D'OR : pas de chevrons <> dans les routes Flask — query params uniquement
"""

import os, uuid, hashlib, datetime, time, re
from functools import wraps
from flask import Flask, request, jsonify, Blueprint
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'postgresql://localhost/coalition509')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'coalition509-dev-secret')
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {'pool_pre_ping': True, 'pool_recycle': 300}
db = SQLAlchemy(app)
CORS(app)

@app.teardown_appcontext
def shutdown_session(exception=None):
    db.session.remove()

def normaliser_tel(phone):
    if not phone: return ''
    t = phone.strip()
    t = re.sub(r"[\s\-\.\(\)]", "", t)
    if t.startswith('+'): t = '00' + t[1:]
    if t.startswith('225') and not t.startswith('00225'): t = '00' + t
    if t.startswith('509') and not t.startswith('00509'): t = '00' + t
    return t

# ============================================================
# MODÈLES EXISTANTS
# ============================================================
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
    source = db.Column(db.String(50), default='unknown')
    messages_sent = db.Column(db.Integer, default=0)
    messages_received = db.Column(db.Integer, default=0)
    unique_users = db.Column(db.Integer, default=0)
    conversions = db.Column(db.Integer, default=0)

# ============================================================
# MODÈLES SHOP
# ============================================================
class Product(db.Model):
    __tablename__ = 'products'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    category = db.Column(db.String(50), default='general')
    price = db.Column(db.Numeric(12, 2), default=0)
    stock_quantity = db.Column(db.Integer, default=0)
    supplier_id = db.Column(db.Integer, db.ForeignKey('suppliers.id'))
    status = db.Column(db.String(20), default='active')
    image_url = db.Column(db.String(500))
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class CartItem(db.Model):
    __tablename__ = 'cart_items'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('products.id'), nullable=False)
    quantity = db.Column(db.Integer, default=1)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class OrderItem(db.Model):
    __tablename__ = 'order_items'
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('orders.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('products.id'), nullable=False)
    quantity = db.Column(db.Integer, default=1)
    unit_price = db.Column(db.Numeric(12, 2), default=0)
    total_price = db.Column(db.Numeric(12, 2), default=0)

class Supplier(db.Model):
    __tablename__ = 'suppliers'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    contact_name = db.Column(db.String(100))
    phone = db.Column(db.String(20))
    email = db.Column(db.String(120))
    region = db.Column(db.String(50))
    commune = db.Column(db.String(50))
    address = db.Column(db.Text)
    status = db.Column(db.String(20), default='active')
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class Delivery(db.Model):
    __tablename__ = 'deliveries'
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('orders.id'), nullable=False)
    supplier_id = db.Column(db.Integer, db.ForeignKey('suppliers.id'))
    status = db.Column(db.String(20), default='pending')
    tracking_number = db.Column(db.String(100))
    address = db.Column(db.Text)
    region = db.Column(db.String(50))
    commune = db.Column(db.String(50))
    estimated_date = db.Column(db.Date)
    delivered_at = db.Column(db.DateTime)
    delivery_person = db.Column(db.String(100))
    delivery_phone = db.Column(db.String(20))
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class Invoice(db.Model):
    __tablename__ = 'invoices'
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('orders.id'), nullable=False)
    invoice_number = db.Column(db.String(50), unique=True, nullable=False)
    amount = db.Column(db.Numeric(12, 2), default=0)
    status = db.Column(db.String(20), default='pending')
    issued_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    paid_at = db.Column(db.DateTime)
    due_date = db.Column(db.Date)

class StockMovement(db.Model):
    __tablename__ = 'stock_movements'
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey('products.id'), nullable=False)
    movement_type = db.Column(db.String(20), default='in')
    quantity = db.Column(db.Integer, default=0)
    reason = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

# ============================================================
# UTILITAIRES
# ============================================================
def hash_pin(pin): return hashlib.sha256(pin.encode()).hexdigest()
def generate_ngd_id(): return f"NGD-{datetime.datetime.now().year}-{uuid.uuid4().hex[:6].upper()}"
def generate_order_number(): return f"CMD-{str(uuid.uuid4().int % 10000).zfill(3)}"
def generate_invoice_number(): return f"FAC-{datetime.datetime.now().year}-{str(uuid.uuid4().int % 10000).zfill(4)}"

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        try:
            token = None
            if 'Authorization' in request.headers:
                parts = request.headers['Authorization'].split()
                if len(parts) == 2 and parts[0] == 'Bearer': token = parts[1]
            if not token:
                token = request.args.get('access_token')
            if not token:
                return jsonify({'status':'error','message':'Token manquant'}), 401
            user = User.query.filter_by(phone=token).first()
            if not user:
                return jsonify({'status':'error','message':'Token invalide'}), 401
            request.current_user = user
            return f(*args, **kwargs)
        except Exception as e:
            import traceback
            print(f"[ERROR token_required] {e}"); traceback.print_exc(); db.session.rollback()
            return jsonify({'status':'error','message':f'Server error: {str(e)}'}), 500
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not hasattr(request, 'current_user') or request.current_user.role != 'admin':
            return jsonify({'status':'error','message':'Accès admin requis'}), 403
        return f(*args, **kwargs)
    return decorated

def build_bot_stats_response():
    try:
        today = datetime.date.today()
        week_ago = today - datetime.timedelta(days=6)
        latest_rows = BotStat.query.filter_by(date=today).all()
        if latest_rows:
            latest = {"leads":sum(r.unique_users or 0 for r in latest_rows),"conversations":sum(r.messages_received or 0 for r in latest_rows),"messages":sum(r.messages_sent or 0 for r in latest_rows),"conversions":sum(r.conversions or 0 for r in latest_rows),"active":sum(r.messages_received or 0 for r in latest_rows),"date":today.isoformat()}
        else:
            since = datetime.datetime.utcnow() - datetime.timedelta(days=1)
            msgs_today = BotMessage.query.filter(BotMessage.created_at >= since).all()
            total_msgs = len(msgs_today)
            unique = BotMessage.query.with_entities(BotMessage.phone).distinct().count()
            latest = {"leads":unique or 0,"conversations":total_msgs,"messages":total_msgs,"conversions":0,"active":total_msgs,"date":today.isoformat()}
        week_rows = BotStat.query.filter(BotStat.date >= week_ago).order_by(BotStat.date.asc()).all()
        by_day = {}
        for r in week_rows:
            d = r.date.strftime("%Y-%m-%d") if r.date else None
            if not d: continue
            by_day.setdefault(d, {"leads":0,"conversations":0,"messages":0,"conversions":0})
            by_day[d]["leads"] += r.unique_users or 0
            by_day[d]["conversations"] += r.messages_received or 0
            by_day[d]["messages"] += r.messages_sent or 0
            by_day[d]["conversions"] += r.conversions or 0
        if not by_day:
            since = datetime.datetime.utcnow() - datetime.timedelta(days=7)
            msgs = BotMessage.query.filter(BotMessage.created_at >= since).all()
            for m in msgs:
                day = m.created_at.strftime('%Y-%m-%d')
                by_day.setdefault(day, {"leads":0,"conversations":0,"messages":0,"conversions":0})
                by_day[day]["messages"] += 1
                by_day[day]["conversations"] += 1
        week = []
        for i in range(7):
            d = (week_ago + datetime.timedelta(days=i)).strftime("%Y-%m-%d")
            week.append({"date":d, **by_day.get(d, {"leads":0,"conversations":0,"messages":0,"conversions":0})})
        return {"latest":latest, "week":week}
    except Exception as e:
        import traceback
        print(f"[ERROR build_bot_stats_response] {e}"); traceback.print_exc(); db.session.rollback()
        today = datetime.date.today(); week_ago = today - datetime.timedelta(days=6)
        week = [{"date":(week_ago + datetime.timedelta(days=i)).strftime("%Y-%m-%d"),"leads":0,"conversations":0,"messages":0,"conversions":0} for i in range(7)]
        return {"latest":{"leads":0,"conversations":0,"messages":0,"conversions":0,"active":0,"date":today.isoformat()}, "week":week}

# ============================================================
# BLUEPRINT : AUTH
# ============================================================
auth_bp = Blueprint('auth', __name__, url_prefix='/api/auth')

@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json() or {}
    phone = normaliser_tel(data.get('phone', ''))
    pin = data.get('pin', '').strip()
    if not phone or not pin:
        return jsonify({'status':'error','message':'Phone et PIN requis'}), 400
    user = User.query.filter_by(phone=phone).first()
    if not user or user.pin_hash != hash_pin(pin):
        return jsonify({'status':'error','message':'Identifiants invalides'}), 401
    if user.status != 'active':
        return jsonify({'status':'error','message':'Compte inactif'}), 403
    return jsonify({'status':'success','token':user.phone,'access_token':user.phone,'user':{'id':user.id,'phone':user.phone,'first_name':user.first_name,'last_name':user.last_name,'email':user.email,'role':user.role,'region':user.region,'commune':user.commune,'profile_type':user.profile_type,'ngd_id':user.ngd_id}})

@auth_bp.route('/register', methods=['POST'])
def register():
    data = request.get_json() or {}
    phone = normaliser_tel(data.get('phone', ''))
    pin = data.get('pin', '').strip()
    first_name = data.get('first_name', '').strip()
    last_name = data.get('last_name', '').strip()
    if not phone or not pin or not first_name or not last_name:
        return jsonify({'status':'error','message':'Champs obligatoires manquants'}), 400
    if User.query.filter_by(phone=phone).first():
        return jsonify({'status':'error','message':'Telephone deja utilise'}), 409
    user = User(phone=phone, pin_hash=hash_pin(pin), first_name=first_name, last_name=last_name,
                email=data.get('email',''), role='user', status='active',
                region=data.get('region',''), commune=data.get('commune',''),
                profile_type=data.get('profile_type','Animateur NGD'), ngd_id=generate_ngd_id())
    db.session.add(user); db.session.commit()
    return jsonify({'status':'success','token':user.phone,'access_token':user.phone,'id':user.id,'ngd_id':user.ngd_id,'user':{'id':user.id,'phone':user.phone,'first_name':user.first_name,'last_name':user.last_name,'email':user.email,'role':user.role,'region':user.region,'commune':user.commune,'profile_type':user.profile_type,'ngd_id':user.ngd_id}}), 201

@auth_bp.route('/me', methods=['GET'])
@token_required
def me():
    u = request.current_user
    return jsonify({'status':'success','user':{'id':u.id,'phone':u.phone,'first_name':u.first_name,'last_name':u.last_name,'email':u.email,'role':u.role,'region':u.region,'commune':u.commune,'profile_type':u.profile_type,'ngd_id':u.ngd_id}})

@auth_bp.route('/verify-bot-token', methods=['POST'])
def verify_bot_token():
    data = request.get_json() or {}
    bot_token = data.get('token', '')
    if not bot_token:
        return jsonify({'ok':False,'error':'Token manquant'}), 400
    try:
        phone = normaliser_tel(bot_token.split('|')[0] if '|' in bot_token else bot_token)
        user = User.query.filter_by(phone=phone).first()
        if user:
            return jsonify({'ok':True,'access_token':user.phone,'user':{'id':user.id,'phone':user.phone,'first_name':user.first_name,'last_name':user.last_name,'email':user.email,'role':user.role,'region':user.region,'commune':user.commune,'profile_type':user.profile_type,'ngd_id':user.ngd_id}})
        else:
            return jsonify({'ok':True,'needs_registration':True,'phone':phone})
    except Exception as e:
        db.session.rollback()
        return jsonify({'ok':False,'error':str(e)}), 400

# ============================================================
# BLUEPRINT : USERS
# ============================================================
users_bp = Blueprint('users', __name__, url_prefix='/api/users')

@users_bp.route('', methods=['GET'])
@token_required
def list_users():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    q = User.query.order_by(User.created_at.desc())
    total = q.count()
    users = q.offset((page-1)*per_page).limit(per_page).all()
    return jsonify({'status':'success','page':page,'per_page':per_page,'total':total,'users':[{'id':u.id,'phone':u.phone,'first_name':u.first_name,'last_name':u.last_name,'email':u.email,'role':u.role,'status':u.status,'region':u.region,'commune':u.commune,'profile_type':u.profile_type,'ngd_id':u.ngd_id,'created_at':u.created_at.isoformat() if u.created_at else None} for u in users]})

# ============================================================
# BLUEPRINT : CAMPAIGNS
# ============================================================
campaigns_bp = Blueprint('campaigns', __name__, url_prefix='/api/campaigns')

@campaigns_bp.route('', methods=['GET'])
@token_required
def list_campaigns():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    q = Campaign.query.order_by(Campaign.created_at.desc())
    total = q.count()
    camps = q.offset((page-1)*per_page).limit(per_page).all()
    return jsonify({'status':'success','page':page,'per_page':per_page,'total':total,'campaigns':[{'id':c.id,'name':c.name,'description':c.description,'election_date':str(c.election_date) if c.election_date else None,'region':c.region,'commune':c.commune,'status':c.status,'created_by':c.created_by,'created_at':c.created_at.isoformat() if c.created_at else None} for c in camps]})

@campaigns_bp.route('', methods=['POST'])
@token_required
def create_campaign():
    data = request.get_json() or {}
    c = Campaign(name=data.get('name',''), description=data.get('description',''),
                 election_date=datetime.datetime.strptime(data['election_date'],'%Y-%m-%d').date() if data.get('election_date') else None,
                 region=data.get('region',''), commune=data.get('commune',''), created_by=request.current_user.id)
    db.session.add(c); db.session.commit()
    return jsonify({'status':'success','campaign':{'id':c.id,'name':c.name}}), 201

@campaigns_bp.route('/detail', methods=['GET'])
@token_required
def get_campaign():
    cid = request.args.get('id', type=int)
    if not cid: return jsonify({'status':'error','message':'id requis'}), 400
    c = Campaign.query.get(cid)
    if not c: return jsonify({'status':'error','message':'Campagne introuvable'}), 404
    return jsonify({'status':'success','campaign':{'id':c.id,'name':c.name,'description':c.description,'election_date':str(c.election_date) if c.election_date else None,'region':c.region,'commune':c.commune,'status':c.status,'created_by':c.created_by,'created_at':c.created_at.isoformat() if c.created_at else None}})

@campaigns_bp.route('/update', methods=['POST'])
@token_required
def update_campaign():
    data = request.get_json() or {}
    cid = data.get('id')
    if not cid: return jsonify({'status':'error','message':'id requis'}), 400
    c = Campaign.query.get(cid)
    if not c: return jsonify({'status':'error','message':'Campagne introuvable'}), 404
    c.name = data.get('name', c.name); c.description = data.get('description', c.description)
    if data.get('election_date'): c.election_date = datetime.datetime.strptime(data['election_date'],'%Y-%m-%d').date()
    c.region = data.get('region', c.region); c.commune = data.get('commune', c.commune); c.status = data.get('status', c.status)
    db.session.commit()
    return jsonify({'status':'success','campaign':{'id':c.id,'name':c.name}})

@campaigns_bp.route('/delete', methods=['POST'])
@token_required
@admin_required
def delete_campaign():
    data = request.get_json() or {}
    cid = data.get('id')
    if not cid: return jsonify({'status':'error','message':'id requis'}), 400
    c = Campaign.query.get(cid)
    if not c: return jsonify({'status':'error','message':'Campagne introuvable'}), 404
    db.session.delete(c); db.session.commit()
    return jsonify({'status':'success','message':'Campagne supprimée'})

# ============================================================
# BLUEPRINT : ORDERS (legacy TCL)
# ============================================================
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
        result.append({'id':o.id,'order_number':o.order_number,'total_amount':float(o.total_amount) if o.total_amount else 0,'status':o.status,'payment_status':o.payment_status,'payment_method':o.payment_method,'region':o.region,'commune':o.commune,'created_at':o.created_at.isoformat() if o.created_at else None,'user':{'id':u.id,'phone':u.phone,'first_name':u.first_name,'last_name':u.last_name,'role':u.role,'region':u.region,'commune':u.commune,'profile_type':u.profile_type,'ngd_id':u.ngd_id} if u else None})
    return jsonify({'status':'success','page':page,'per_page':per_page,'total':total,'orders':result})

@orders_bp.route('/detail', methods=['GET'])
@token_required
def get_order():
    oid = request.args.get('id', type=int)
    if not oid: return jsonify({'status':'error','message':'id requis'}), 400
    o = Order.query.get(oid)
    if not o: return jsonify({'status':'error','message':'Commande introuvable'}), 404
    u = User.query.get(o.user_id)
    items = OrderItem.query.filter_by(order_id=o.id).all()
    items_out = []
    for it in items:
        p = Product.query.get(it.product_id)
        items_out.append({'id':it.id,'product_id':it.product_id,'product_name':p.name if p else '—','quantity':it.quantity,'unit_price':float(it.unit_price),'total_price':float(it.total_price)})
    return jsonify({'status':'success','order':{'id':o.id,'order_number':o.order_number,'total_amount':float(o.total_amount) if o.total_amount else 0,'status':o.status,'payment_status':o.payment_status,'payment_method':o.payment_method,'region':o.region,'commune':o.commune,'created_at':o.created_at.isoformat() if o.created_at else None,'user':{'id':u.id,'phone':u.phone,'first_name':u.first_name,'last_name':u.last_name} if u else None,'items':items_out}})

@orders_bp.route('/pay', methods=['POST'])
@token_required
def pay_order():
    data = request.get_json() or {}
    oid = data.get('id') or data.get('order_id')
    method = data.get('payment_method','mobile_money')
    if not oid: return jsonify({'status':'error','message':'id requis'}), 400
    o = Order.query.get(oid)
    if not o: return jsonify({'status':'error','message':'Commande introuvable'}), 404
    o.payment_status = 'paid'; o.payment_method = method; o.status = 'completed'
    db.session.commit()
    return jsonify({'status':'success','message':'Paiement enregistre','order':{'id':o.id,'payment_status':o.payment_status}})

# ============================================================
# BLUEPRINT : SHOP
# ============================================================
shop_bp = Blueprint('shop', __name__, url_prefix='/api/shop')

@shop_bp.route('/products', methods=['GET'])
@token_required
def shop_list_products():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    cat = request.args.get('category', '')
    q = Product.query
    if cat: q = q.filter_by(category=cat)
    q = q.order_by(Product.created_at.desc())
    total = q.count()
    products = q.offset((page-1)*per_page).limit(per_page).all()
    return jsonify({'status':'success','page':page,'per_page':per_page,'total':total,'products':[{'id':p.id,'name':p.name,'description':p.description,'category':p.category,'price':float(p.price),'stock_quantity':p.stock_quantity,'supplier_id':p.supplier_id,'status':p.status,'image_url':p.image_url,'created_at':p.created_at.isoformat() if p.created_at else None} for p in products]})

@shop_bp.route('/products', methods=['POST'])
@token_required
@admin_required
def shop_create_product():
    data = request.get_json() or {}
    p = Product(name=data.get('name',''), description=data.get('description',''), category=data.get('category','general'),
                price=data.get('price',0), stock_quantity=data.get('stock_quantity',0), supplier_id=data.get('supplier_id'),
                status=data.get('status','active'), image_url=data.get('image_url',''))
    db.session.add(p); db.session.commit()
    return jsonify({'status':'success','product':{'id':p.id,'name':p.name}}), 201

@shop_bp.route('/products/detail', methods=['GET'])
@token_required
def shop_get_product():
    pid = request.args.get('id', type=int)
    if not pid: return jsonify({'status':'error','message':'id requis'}), 400
    p = Product.query.get(pid)
    if not p: return jsonify({'status':'error','message':'Produit introuvable'}), 404
    return jsonify({'status':'success','product':{'id':p.id,'name':p.name,'description':p.description,'category':p.category,'price':float(p.price),'stock_quantity':p.stock_quantity,'supplier_id':p.supplier_id,'status':p.status,'image_url':p.image_url}})

@shop_bp.route('/products/update', methods=['POST'])
@token_required
@admin_required
def shop_update_product():
    data = request.get_json() or {}
    pid = data.get('id')
    if not pid: return jsonify({'status':'error','message':'id requis'}), 400
    p = Product.query.get(pid)
    if not p: return jsonify({'status':'error','message':'Produit introuvable'}), 404
    p.name = data.get('name', p.name); p.description = data.get('description', p.description)
    p.category = data.get('category', p.category); p.price = data.get('price', p.price)
    p.stock_quantity = data.get('stock_quantity', p.stock_quantity); p.supplier_id = data.get('supplier_id', p.supplier_id)
    p.status = data.get('status', p.status); p.image_url = data.get('image_url', p.image_url)
    db.session.commit()
    return jsonify({'status':'success','product':{'id':p.id,'name':p.name}})

@shop_bp.route('/products/delete', methods=['POST'])
@token_required
@admin_required
def shop_delete_product():
    data = request.get_json() or {}
    pid = data.get('id')
    if not pid: return jsonify({'status':'error','message':'id requis'}), 400
    p = Product.query.get(pid)
    if not p: return jsonify({'status':'error','message':'Produit introuvable'}), 404
    db.session.delete(p); db.session.commit()
    return jsonify({'status':'success','message':'Produit supprimé'})

@shop_bp.route('/cart', methods=['GET'])
@token_required
def shop_get_cart():
    user_id = request.current_user.id
    items = CartItem.query.filter_by(user_id=user_id).all()
    result = []; total = 0
    for it in items:
        p = Product.query.get(it.product_id)
        if p:
            sub = float(p.price) * it.quantity; total += sub
            result.append({'id':it.id,'product_id':p.id,'name':p.name,'price':float(p.price),'quantity':it.quantity,'subtotal':sub,'image_url':p.image_url})
    return jsonify({'status':'success','items':result,'total':total,'count':len(result)})

@shop_bp.route('/cart/add', methods=['POST'])
@token_required
def shop_add_cart():
    data = request.get_json() or {}
    user_id = request.current_user.id
    product_id = data.get('product_id'); qty = data.get('quantity', 1)
    if not product_id: return jsonify({'status':'error','message':'product_id requis'}), 400
    existing = CartItem.query.filter_by(user_id=user_id, product_id=product_id).first()
    if existing: existing.quantity += qty
    else: db.session.add(CartItem(user_id=user_id, product_id=product_id, quantity=qty))
    db.session.commit()
    return jsonify({'status':'success','message':'Ajouté au panier'})

@shop_bp.route('/cart/remove', methods=['POST'])
@token_required
def shop_remove_cart():
    data = request.get_json() or {}
    cid = data.get('id')
    if not cid: return jsonify({'status':'error','message':'id requis'}), 400
    item = CartItem.query.get(cid)
    if item and item.user_id == request.current_user.id:
        db.session.delete(item); db.session.commit()
    return jsonify({'status':'success','message':'Retiré du panier'})

@shop_bp.route('/cart/clear', methods=['POST'])
@token_required
def shop_clear_cart():
    CartItem.query.filter_by(user_id=request.current_user.id).delete()
    db.session.commit()
    return jsonify({'status':'success','message':'Panier vidé'})

@shop_bp.route('/orders', methods=['GET'])
@token_required
def shop_list_orders():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    q = Order.query.order_by(Order.created_at.desc())
    total = q.count()
    orders = q.offset((page-1)*per_page).limit(per_page).all()
    result = []
    for o in orders:
        u = User.query.get(o.user_id)
        items = OrderItem.query.filter_by(order_id=o.id).all()
        items_out = []
        for it in items:
            p = Product.query.get(it.product_id)
            items_out.append({'id':it.id,'product_name':p.name if p else '—','quantity':it.quantity,'unit_price':float(it.unit_price),'total_price':float(it.total_price)})
        result.append({'id':o.id,'order_number':o.order_number,'total_amount':float(o.total_amount) if o.total_amount else 0,'status':o.status,'payment_status':o.payment_status,'payment_method':o.payment_method,'region':o.region,'commune':o.commune,'created_at':o.created_at.isoformat() if o.created_at else None,'user':{'id':u.id,'phone':u.phone,'first_name':u.first_name,'last_name':u.last_name} if u else None,'items':items_out})
    return jsonify({'status':'success','page':page,'per_page':per_page,'total':total,'orders':result})

@shop_bp.route('/orders/create', methods=['POST'])
@token_required
def shop_create_order():
    user_id = request.current_user.id
    data = request.get_json() or {}
    cart_items = CartItem.query.filter_by(user_id=user_id).all()
    if not cart_items: return jsonify({'status':'error','message':'Panier vide'}), 400
    total = 0
    order = Order(order_number=generate_order_number(), user_id=user_id, total_amount=0,
                  status='pending', payment_status='pending', region=data.get('region',''), commune=data.get('commune',''))
    db.session.add(order); db.session.commit()

    # Suivi des fournisseurs concernés pour livraison auto
    suppliers_map = {}  # supplier_id -> {'items': [], 'subtotal': 0}

    for ci in cart_items:
        p = Product.query.get(ci.product_id)
        if not p: continue
        sub = float(p.price) * ci.quantity; total += sub
        db.session.add(OrderItem(order_id=order.id, product_id=p.id, quantity=ci.quantity, unit_price=p.price, total_price=sub))
        p.stock_quantity = max(0, (p.stock_quantity or 0) - ci.quantity)
        db.session.add(StockMovement(product_id=p.id, movement_type='out', quantity=ci.quantity, reason=f'Commande {order.order_number}'))

        # Sélection auto fournisseur par produit
        if p.supplier_id:
            if p.supplier_id not in suppliers_map:
                suppliers_map[p.supplier_id] = {'items': [], 'subtotal': 0}
            suppliers_map[p.supplier_id]['items'].append(p.name)
            suppliers_map[p.supplier_id]['subtotal'] += sub

    order.total_amount = total

    # === AUTO-FACTURE ===
    invoice = Invoice(
        order_id=order.id,
        invoice_number=generate_invoice_number(),
        amount=total,
        status='pending',
        due_date=datetime.date.today() + datetime.timedelta(days=7)
    )
    db.session.add(invoice)

    # === AUTO-LIVRAISON + SÉLECTION AUTO FOURNISSEUR & LIVREUR ===
    deliveries_created = []
    if suppliers_map:
        for sid, info in suppliers_map.items():
            supplier = Supplier.query.get(sid)
            if supplier:
                # Livreur = contact du fournisseur (sélection auto)
                delivery = Delivery(
                    order_id=order.id,
                    supplier_id=supplier.id,
                    status='pending',
                    address=supplier.address or data.get('address',''),
                    region=supplier.region or data.get('region',''),
                    commune=supplier.commune or data.get('commune',''),
                    estimated_date=datetime.date.today() + datetime.timedelta(days=3),
                    delivery_person=supplier.contact_name or 'Livreur assigné',
                    delivery_phone=supplier.phone or '',
                    notes=f"Livraison auto — {len(info['items'])} article(s): {', '.join(info['items'][:3])}{'...' if len(info['items']) > 3 else ''}"
                )
                db.session.add(delivery)
                deliveries_created.append({
                    'id': delivery.id,
                    'supplier_name': supplier.name,
                    'delivery_person': delivery.delivery_person,
                    'delivery_phone': delivery.delivery_phone,
                    'estimated_date': str(delivery.estimated_date),
                    'status': delivery.status
                })
    else:
        # Aucun fournisseur identifié — livraison générique
        delivery = Delivery(
            order_id=order.id,
            status='pending',
            region=data.get('region',''),
            commune=data.get('commune',''),
            estimated_date=datetime.date.today() + datetime.timedelta(days=3),
            delivery_person="Livreur en attente d'assignation",
            notes='Livraison générique — fournisseur non identifié'
        )
        db.session.add(delivery)
        deliveries_created.append({
            'id': delivery.id,
            'supplier_name': None,
            'delivery_person': delivery.delivery_person,
            'delivery_phone': '',
            'estimated_date': str(delivery.estimated_date),
            'status': delivery.status
        })

    CartItem.query.filter_by(user_id=user_id).delete()
    db.session.commit()

    return jsonify({
        'status':'success',
        'order':{'id':order.id,'order_number':order.order_number,'total_amount':float(total)},
        'invoice':{'invoice_number':invoice.invoice_number,'amount':float(invoice.amount),'status':invoice.status,'due_date':str(invoice.due_date)},
        'deliveries':deliveries_created
    }), 201

@shop_bp.route('/orders/detail', methods=['GET'])
@token_required
def shop_get_order():
    oid = request.args.get('id', type=int)
    if not oid: return jsonify({'status':'error','message':'id requis'}), 400
    o = Order.query.get(oid)
    if not o: return jsonify({'status':'error','message':'Commande introuvable'}), 404
    u = User.query.get(o.user_id)
    items = OrderItem.query.filter_by(order_id=o.id).all()
    items_out = []
    for it in items:
        p = Product.query.get(it.product_id)
        items_out.append({'id':it.id,'product_name':p.name if p else '—','quantity':it.quantity,'unit_price':float(it.unit_price),'total_price':float(it.total_price)})
    inv = Invoice.query.filter_by(order_id=o.id).first()
    deliveries = Delivery.query.filter_by(order_id=o.id).all()
    deliveries_out = []
    for d in deliveries:
        s = Supplier.query.get(d.supplier_id) if d.supplier_id else None
        deliveries_out.append({
            'id':d.id,
            'status':d.status,
            'tracking_number':d.tracking_number,
            'estimated_date':str(d.estimated_date) if d.estimated_date else None,
            'delivered_at':d.delivered_at.isoformat() if d.delivered_at else None,
            'supplier':{'id':s.id,'name':s.name,'phone':s.phone} if s else None,
            'delivery_person':d.delivery_person,
            'delivery_phone':d.delivery_phone,
            'address':d.address,
            'notes':d.notes
        })
    return jsonify({'status':'success','order':{'id':o.id,'order_number':o.order_number,'total_amount':float(o.total_amount) if o.total_amount else 0,'status':o.status,'payment_status':o.payment_status,'payment_method':o.payment_method,'region':o.region,'commune':o.commune,'created_at':o.created_at.isoformat() if o.created_at else None,'user':{'id':u.id,'phone':u.phone,'first_name':u.first_name,'last_name':u.last_name} if u else None,'items':items_out,'invoice':{'id':inv.id,'invoice_number':inv.invoice_number,'amount':float(inv.amount),'status':inv.status} if inv else None,'deliveries':deliveries_out}})

@shop_bp.route('/orders/update', methods=['POST'])
@token_required
@admin_required
def shop_update_order():
    data = request.get_json() or {}
    oid = data.get('id')
    if not oid: return jsonify({'status':'error','message':'id requis'}), 400
    o = Order.query.get(oid)
    if not o: return jsonify({'status':'error','message':'Commande introuvable'}), 404
    o.status = data.get('status', o.status); o.payment_status = data.get('payment_status', o.payment_status)
    o.payment_method = data.get('payment_method', o.payment_method)
    db.session.commit()
    return jsonify({'status':'success','order':{'id':o.id,'status':o.status}})

@shop_bp.route('/orders/delete', methods=['POST'])
@token_required
@admin_required
def shop_delete_order():
    data = request.get_json() or {}
    oid = data.get('id')
    if not oid: return jsonify({'status':'error','message':'id requis'}), 400
    o = Order.query.get(oid)
    if not o: return jsonify({'status':'error','message':'Commande introuvable'}), 404
    OrderItem.query.filter_by(order_id=o.id).delete()
    Delivery.query.filter_by(order_id=o.id).delete()
    Invoice.query.filter_by(order_id=o.id).delete()
    db.session.delete(o); db.session.commit()
    return jsonify({'status':'success','message':'Commande supprimée'})

@shop_bp.route('/suppliers', methods=['GET'])
@token_required
def shop_list_suppliers():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    q = Supplier.query.order_by(Supplier.created_at.desc())
    total = q.count()
    suppliers = q.offset((page-1)*per_page).limit(per_page).all()
    return jsonify({'status':'success','page':page,'per_page':per_page,'total':total,'suppliers':[{'id':s.id,'name':s.name,'contact_name':s.contact_name,'phone':s.phone,'email':s.email,'region':s.region,'commune':s.commune,'address':s.address,'status':s.status,'created_at':s.created_at.isoformat() if s.created_at else None} for s in suppliers]})

@shop_bp.route('/suppliers', methods=['POST'])
@token_required
@admin_required
def shop_create_supplier():
    data = request.get_json() or {}
    s = Supplier(name=data.get('name',''), contact_name=data.get('contact_name',''), phone=data.get('phone',''),
                 email=data.get('email',''), region=data.get('region',''), commune=data.get('commune',''),
                 address=data.get('address',''), status=data.get('status','active'))
    db.session.add(s); db.session.commit()
    return jsonify({'status':'success','supplier':{'id':s.id,'name':s.name}}), 201

@shop_bp.route('/suppliers/detail', methods=['GET'])
@token_required
def shop_get_supplier():
    sid = request.args.get('id', type=int)
    if not sid: return jsonify({'status':'error','message':'id requis'}), 400
    s = Supplier.query.get(sid)
    if not s: return jsonify({'status':'error','message':'Fournisseur introuvable'}), 404
    return jsonify({'status':'success','supplier':{'id':s.id,'name':s.name,'contact_name':s.contact_name,'phone':s.phone,'email':s.email,'region':s.region,'commune':s.commune,'address':s.address,'status':s.status}})

@shop_bp.route('/suppliers/update', methods=['POST'])
@token_required
@admin_required
def shop_update_supplier():
    data = request.get_json() or {}
    sid = data.get('id')
    if not sid: return jsonify({'status':'error','message':'id requis'}), 400
    s = Supplier.query.get(sid)
    if not s: return jsonify({'status':'error','message':'Fournisseur introuvable'}), 404
    s.name = data.get('name', s.name); s.contact_name = data.get('contact_name', s.contact_name)
    s.phone = data.get('phone', s.phone); s.email = data.get('email', s.email)
    s.region = data.get('region', s.region); s.commune = data.get('commune', s.commune)
    s.address = data.get('address', s.address); s.status = data.get('status', s.status)
    db.session.commit()
    return jsonify({'status':'success','supplier':{'id':s.id,'name':s.name}})

@shop_bp.route('/suppliers/delete', methods=['POST'])
@token_required
@admin_required
def shop_delete_supplier():
    data = request.get_json() or {}
    sid = data.get('id')
    if not sid: return jsonify({'status':'error','message':'id requis'}), 400
    s = Supplier.query.get(sid)
    if not s: return jsonify({'status':'error','message':'Fournisseur introuvable'}), 404
    db.session.delete(s); db.session.commit()
    return jsonify({'status':'success','message':'Fournisseur supprimé'})

@shop_bp.route('/deliveries', methods=['GET'])
@token_required
def shop_list_deliveries():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    q = Delivery.query.order_by(Delivery.created_at.desc())
    total = q.count()
    deliveries = q.offset((page-1)*per_page).limit(per_page).all()
    result = []
    for d in deliveries:
        o = Order.query.get(d.order_id)
        s = Supplier.query.get(d.supplier_id) if d.supplier_id else None
        result.append({'id':d.id,'order_id':d.order_id,'order_number':o.order_number if o else '—','status':d.status,'tracking_number':d.tracking_number,'address':d.address,'region':d.region,'commune':d.commune,'estimated_date':str(d.estimated_date) if d.estimated_date else None,'delivered_at':d.delivered_at.isoformat() if d.delivered_at else None,'delivery_person':d.delivery_person,'delivery_phone':d.delivery_phone,'supplier_name':s.name if s else '—','notes':d.notes,'created_at':d.created_at.isoformat() if d.created_at else None})
    return jsonify({'status':'success','page':page,'per_page':per_page,'total':total,'deliveries':result})

@shop_bp.route('/deliveries', methods=['POST'])
@token_required
@admin_required
def shop_create_delivery():
    data = request.get_json() or {}
    d = Delivery(order_id=data.get('order_id'), status=data.get('status','pending'), tracking_number=data.get('tracking_number',''),
                 address=data.get('address',''), region=data.get('region',''), commune=data.get('commune',''),
                 estimated_date=datetime.datetime.strptime(data['estimated_date'],'%Y-%m-%d').date() if data.get('estimated_date') else None,
                 notes=data.get('notes',''))
    db.session.add(d); db.session.commit()
    return jsonify({'status':'success','delivery':{'id':d.id,'order_id':d.order_id}}), 201

@shop_bp.route('/deliveries/detail', methods=['GET'])
@token_required
def shop_get_delivery():
    did = request.args.get('id', type=int)
    if not did: return jsonify({'status':'error','message':'id requis'}), 400
    d = Delivery.query.get(did)
    if not d: return jsonify({'status':'error','message':'Livraison introuvable'}), 404
    return jsonify({'status':'success','delivery':{'id':d.id,'order_id':d.order_id,'status':d.status,'tracking_number':d.tracking_number,'address':d.address,'region':d.region,'commune':d.commune,'estimated_date':str(d.estimated_date) if d.estimated_date else None,'delivered_at':d.delivered_at.isoformat() if d.delivered_at else None,'notes':d.notes}})

@shop_bp.route('/deliveries/update', methods=['POST'])
@token_required
@admin_required
def shop_update_delivery():
    data = request.get_json() or {}
    did = data.get('id')
    if not did: return jsonify({'status':'error','message':'id requis'}), 400
    d = Delivery.query.get(did)
    if not d: return jsonify({'status':'error','message':'Livraison introuvable'}), 404
    d.status = data.get('status', d.status); d.tracking_number = data.get('tracking_number', d.tracking_number)
    d.address = data.get('address', d.address); d.region = data.get('region', d.region)
    d.commune = data.get('commune', d.commune); d.notes = data.get('notes', d.notes)
    d.delivery_person = data.get('delivery_person', d.delivery_person)
    d.delivery_phone = data.get('delivery_phone', d.delivery_phone)
    if data.get('supplier_id'): d.supplier_id = data.get('supplier_id')
    if data.get('estimated_date'): d.estimated_date = datetime.datetime.strptime(data['estimated_date'],'%Y-%m-%d').date()
    if data.get('delivered_at'): d.delivered_at = datetime.datetime.strptime(data['delivered_at'],'%Y-%m-%dT%H:%M:%S')
    db.session.commit()
    return jsonify({'status':'success','delivery':{'id':d.id,'status':d.status}})

@shop_bp.route('/invoices', methods=['GET'])
@token_required
def shop_list_invoices():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    q = Invoice.query.order_by(Invoice.issued_at.desc())
    total = q.count()
    invoices = q.offset((page-1)*per_page).limit(per_page).all()
    result = []
    for inv in invoices:
        o = Order.query.get(inv.order_id)
        result.append({'id':inv.id,'order_id':inv.order_id,'order_number':o.order_number if o else '—','invoice_number':inv.invoice_number,'amount':float(inv.amount),'status':inv.status,'issued_at':inv.issued_at.isoformat() if inv.issued_at else None,'paid_at':inv.paid_at.isoformat() if inv.paid_at else None,'due_date':str(inv.due_date) if inv.due_date else None})
    return jsonify({'status':'success','page':page,'per_page':per_page,'total':total,'invoices':result})

@shop_bp.route('/invoices', methods=['POST'])
@token_required
@admin_required
def shop_create_invoice():
    data = request.get_json() or {}
    inv = Invoice(order_id=data.get('order_id'), invoice_number=generate_invoice_number(),
                  amount=data.get('amount',0), status=data.get('status','pending'),
                  due_date=datetime.datetime.strptime(data['due_date'],'%Y-%m-%d').date() if data.get('due_date') else None)
    db.session.add(inv); db.session.commit()
    return jsonify({'status':'success','invoice':{'id':inv.id,'invoice_number':inv.invoice_number}}), 201

@shop_bp.route('/invoices/detail', methods=['GET'])
@token_required
def shop_get_invoice():
    iid = request.args.get('id', type=int)
    if not iid: return jsonify({'status':'error','message':'id requis'}), 400
    inv = Invoice.query.get(iid)
    if not inv: return jsonify({'status':'error','message':'Facture introuvable'}), 404
    return jsonify({'status':'success','invoice':{'id':inv.id,'order_id':inv.order_id,'invoice_number':inv.invoice_number,'amount':float(inv.amount),'status':inv.status,'issued_at':inv.issued_at.isoformat() if inv.issued_at else None,'paid_at':inv.paid_at.isoformat() if inv.paid_at else None,'due_date':str(inv.due_date) if inv.due_date else None}})

@shop_bp.route('/invoices/update', methods=['POST'])
@token_required
@admin_required
def shop_update_invoice():
    data = request.get_json() or {}
    iid = data.get('id')
    if not iid: return jsonify({'status':'error','message':'id requis'}), 400
    inv = Invoice.query.get(iid)
    if not inv: return jsonify({'status':'error','message':'Facture introuvable'}), 404
    inv.status = data.get('status', inv.status)
    if data.get('status') == 'paid' and inv.status != 'paid': inv.paid_at = datetime.datetime.utcnow()
    inv.amount = data.get('amount', inv.amount)
    if data.get('due_date'): inv.due_date = datetime.datetime.strptime(data['due_date'],'%Y-%m-%d').date()
    db.session.commit()
    return jsonify({'status':'success','invoice':{'id':inv.id,'status':inv.status}})

@shop_bp.route('/stock-movements', methods=['GET'])
@token_required
def shop_list_stock():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    product_id = request.args.get('product_id', type=int)
    q = StockMovement.query.order_by(StockMovement.created_at.desc())
    if product_id: q = q.filter_by(product_id=product_id)
    total = q.count()
    movements = q.offset((page-1)*per_page).limit(per_page).all()
    result = []
    for m in movements:
        p = Product.query.get(m.product_id)
        result.append({'id':m.id,'product_id':m.product_id,'product_name':p.name if p else '—','movement_type':m.movement_type,'quantity':m.quantity,'reason':m.reason,'created_at':m.created_at.isoformat() if m.created_at else None})
    return jsonify({'status':'success','page':page,'per_page':per_page,'total':total,'movements':result})

@shop_bp.route('/stock-movements/add', methods=['POST'])
@token_required
@admin_required
def shop_add_stock():
    data = request.get_json() or {}
    pid = data.get('product_id'); qty = data.get('quantity', 0); mtype = data.get('movement_type', 'in')
    if not pid: return jsonify({'status':'error','message':'product_id requis'}), 400
    p = Product.query.get(pid)
    if not p: return jsonify({'status':'error','message':'Produit introuvable'}), 404
    if mtype == 'in': p.stock_quantity = (p.stock_quantity or 0) + qty
    else: p.stock_quantity = max(0, (p.stock_quantity or 0) - qty)
    db.session.add(StockMovement(product_id=pid, movement_type=mtype, quantity=qty, reason=data.get('reason','Ajustement manuel')))
    db.session.commit()
    return jsonify({'status':'success','message':'Stock mis à jour','product':{'id':p.id,'stock_quantity':p.stock_quantity}})

@shop_bp.route('/stock-movements/product', methods=['GET'])
@token_required
def shop_stock_by_product():
    pid = request.args.get('id', type=int)
    if not pid: return jsonify({'status':'error','message':'id requis'}), 400
    p = Product.query.get(pid)
    if not p: return jsonify({'status':'error','message':'Produit introuvable'}), 404
    movements = StockMovement.query.filter_by(product_id=pid).order_by(StockMovement.created_at.desc()).all()
    return jsonify({'status':'success','product':{'id':p.id,'name':p.name,'stock_quantity':p.stock_quantity},'movements':[{'id':m.id,'movement_type':m.movement_type,'quantity':m.quantity,'reason':m.reason,'created_at':m.created_at.isoformat() if m.created_at else None} for m in movements]})

# ============================================================
# BLUEPRINT : STATS
# ============================================================
stats_bp = Blueprint('stats', __name__, url_prefix='/api/stats')

@stats_bp.route('/overview', methods=['GET'])
@token_required
def stats_overview():
    try:
        total_users = User.query.count(); total_campaigns = Campaign.query.filter_by(status='active').count(); total_orders = Order.query.count()
        pending_orders = Order.query.filter_by(payment_status='pending').count()
        paid_orders = Order.query.filter_by(payment_status='paid').count()
        total_revenue = db.session.query(db.func.sum(Order.total_amount)).filter_by(payment_status='paid').scalar() or 0
        total_products = Product.query.count(); low_stock = Product.query.filter(Product.stock_quantity <= 5).count()
        total_suppliers = Supplier.query.count(); total_invoices = Invoice.query.count()
        return jsonify({'status':'success','stats':{'total_users':total_users,'total_campaigns':total_campaigns,'total_orders':total_orders,'pending_orders':pending_orders,'paid_orders':paid_orders,'total_revenue':float(total_revenue),'total_products':total_products,'low_stock':low_stock,'total_suppliers':total_suppliers,'total_invoices':total_invoices}})
    except Exception as e:
        db.session.rollback()
        import traceback
        traceback.print_exc()
        return jsonify({'status':'error','message':str(e)}), 500

# ============================================================
# BLUEPRINT : BOT
# ============================================================
bot_bp = Blueprint('bot', __name__, url_prefix='/api/bot')

@bot_bp.route('/stats', methods=['GET'])
def bot_stats():
    try:
        return jsonify(build_bot_stats_response())
    except Exception as e:
        db.session.rollback()
        import traceback
        traceback.print_exc()
        today = datetime.date.today(); week_ago = today - datetime.timedelta(days=6)
        week = [{"date":(week_ago + datetime.timedelta(days=i)).strftime("%Y-%m-%d"),"leads":0,"conversations":0,"messages":0,"conversions":0} for i in range(7)]
        return jsonify({"latest":{"leads":0,"conversations":0,"messages":0,"conversions":0,"active":0,"date":today.isoformat()}, "week":week})

@bot_bp.route('/stats/history', methods=['GET'])
@token_required
def bot_stats_history():
    try:
        days = request.args.get('days', 7, type=int)
        since = datetime.datetime.utcnow() - datetime.timedelta(days=days)
        msgs = BotMessage.query.filter(BotMessage.created_at >= since).all()
        by_day = {}
        for m in msgs:
            day = m.created_at.strftime('%Y-%m-%d')
            by_day.setdefault(day, {'conversations':0,'leads':0,'messages':0})
            by_day[day]['messages'] += 1; by_day[day]['conversations'] += 1
        result = [{'date':d,'conversations':by_day[d]['conversations'],'leads':by_day[d]['leads'],'messages':by_day[d]['messages']} for d in sorted(by_day.keys())]
        return jsonify(result)
    except Exception as e:
        db.session.rollback()
        import traceback
        traceback.print_exc()
        return jsonify([])

@bot_bp.route('/stats', methods=['POST'])
def bot_stats_post():
    try:
        data = request.get_json() or {}
        api_key = request.headers.get('X-Bot-API-Key','')
        if api_key != os.environ.get('BOT_API_KEY','coalition509-bot-secret-2026'):
            return jsonify({'status':'error','message':'Unauthorized'}), 401
        today = datetime.date.today(); source = data.get('source','unknown')
        stat = BotStat.query.filter_by(date=today, source=source).first()
        if not stat: stat = BotStat(date=today, source=source); db.session.add(stat)
        stat.unique_users = max(stat.unique_users or 0, data.get('leads',0))
        stat.messages_received = max(stat.messages_received or 0, data.get('conversations',0))
        stat.messages_sent = max(stat.messages_sent or 0, data.get('messages',0))
        stat.conversions = max(stat.conversions or 0, data.get('conversions',0))
        db.session.commit()
        return jsonify({'status':'success'})
    except Exception as e:
        db.session.rollback()
        import traceback
        traceback.print_exc()
        return jsonify({'status':'error','message':str(e)}), 500

@bot_bp.route('/generate-token', methods=['POST'])
def generate_bot_token():
    try:
        api_key = request.headers.get('X-Bot-Key','') or request.headers.get('X-Bot-API-Key','')
        if api_key != os.environ.get('BOT_API_KEY','coalition509-bot-secret-2026'):
            return jsonify({'status':'error','message':'Unauthorized'}), 401
        data = request.get_json() or {}
        phone = normaliser_tel(data.get('phone',''))
        if not phone: return jsonify({'status':'error','message':'Phone requis'}), 400
        token_raw = f"{phone}|{int(time.time())}|{app.config['SECRET_KEY']}"
        token = hashlib.sha256(token_raw.encode()).hexdigest()[:32]
        return jsonify({'token':f"{phone}|{token}"})
    except Exception as e:
        db.session.rollback()
        import traceback
        traceback.print_exc()
        return jsonify({'status':'error','message':str(e)}), 500

# ============================================================
# BLUEPRINTS INIT / SEED
# ============================================================
init_bp = Blueprint('init', __name__, url_prefix='/api')

@init_bp.route('/init-db', methods=['GET'])
def init_db():
    try:
        db.drop_all(); db.create_all()
        return jsonify({'status':'success','message':'Base de donnees reinitialisee (soft reset)'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'status':'error','message':str(e)}), 500

seed_bp = Blueprint('seed', __name__, url_prefix='/api')

@seed_bp.route('/seed', methods=['GET','POST'])
def seed():
    try:
        db.session.query(StockMovement).delete(); db.session.query(Invoice).delete()
        db.session.query(Delivery).delete(); db.session.query(OrderItem).delete()
        db.session.query(CartItem).delete(); db.session.query(Product).delete()
        db.session.query(Supplier).delete()
        db.session.query(Order).delete(); db.session.query(Campaign).delete(); db.session.query(User).delete()
        db.session.commit()

        users_data = [
            ('002250707777701', '1234', 'Jean', 'Kouassi', 'jean@coalition509.ci', 'admin', 'active', 'Abidjan', 'Cocody', 'Superviseur'),
            ('002250707777702', '1234', 'Marie', 'Yao', 'marie@coalition509.ci', 'admin', 'active', 'Abidjan', 'Plateau', 'Superviseur'),
            ('002250707777703', '1234', 'Koffi', 'Bamba', 'koffi@coalition509.ci', 'user', 'active', 'Bouaké', 'Bouaké', 'Animateur NGD'),
            ('002250707777704', '1234', 'Aminata', 'Diallo', 'aminata@coalition509.ci', 'user', 'active', 'Yamoussoukro', 'Yamoussoukro', 'Animateur NGD'),
            ('002250707777705', '1234', 'Yao', 'Kouamé', 'yao@coalition509.ci', 'user', 'active', 'San-Pédro', 'San-Pédro', 'Animateur NGD'),
            ('002250707777706', '1234', 'Fatou', "N'Guessan", 'fatou@coalition509.ci', 'user', 'active', 'Korhogo', 'Korhogo', 'Animateur NGD'),
            ('002250707777707', '1234', 'Emmanuel', 'Koné', 'emmanuel@coalition509.ci', 'user', 'active', 'Daloa', 'Daloa', 'Animateur NGD'),
            ('002250707777708', '1234', 'Rose', 'Achi', 'rose@coalition509.ci', 'user', 'active', 'Man', 'Man', 'Animateur NGD'),
            ('002250707777709', '1234', 'Paul', 'Bété', 'paul@coalition509.ci', 'user', 'active', 'Abidjan', 'Marcory', 'Animateur NGD'),
        ]
        created_users = []
        for phone, pin, fn, ln, email, role, status, region, commune, ptype in users_data:
            u = User(phone=phone, pin_hash=hash_pin(pin), first_name=fn, last_name=ln, email=email,
                     role=role, status=status, region=region, commune=commune, profile_type=ptype, ngd_id=generate_ngd_id())
            db.session.add(u); db.session.commit()
            created_users.append(u)

        campaigns_data = [
            ('Campagne Présidentielle 2025', 'Mobilisation nationale pour les élections présidentielles.', datetime.date(2025,10,25), 'Abidjan', 'Cocody', 'inactive', created_users[0].id),
            ('Campagne Législatives Sud', 'Campagne législative pour les circonscriptions du sud.', datetime.date(2025,11,15), 'Abidjan', 'Marcory', 'inactive', created_users[1].id),
            ('Campagne Municipales Cocody', 'Élections municipales — commune de Cocody.', datetime.date(2025,12,1), 'Abidjan', 'Cocody', 'inactive', created_users[0].id),
            ('Campagne Régionale Savanes', 'Élections régionales dans la région des Savanes.', datetime.date(2025,11,30), 'Korhogo', 'Korhogo', 'inactive', created_users[5].id),
        ]
        created_campaigns = []
        for name, desc, edate, region, commune, status, created_by in campaigns_data:
            c = Campaign(name=name, description=desc, election_date=edate, region=region, commune=commune, status=status, created_by=created_by)
            db.session.add(c); db.session.commit()
            created_campaigns.append(c)

        s1 = Supplier(name='TCL Distribution CI', contact_name='Pierre Durand', phone='002250707777710', email='tcl@coalition509.ci', region='Abidjan', commune='Cocody', address='12 Boulevard Latrille', status='active')
        s2 = Supplier(name='PrintPro CI', contact_name='Marie Luce', phone='002250707777711', email='print@coalition509.ci', region='Abidjan', commune='Plateau', address='45 Avenue Champs de Mars', status='active')
        db.session.add_all([s1,s2]); db.session.commit()

        products_data = [
            ('Affiche A3 (lot 100)', 'Affiches électorales haute qualité format A3', 'imprimerie', 3500, 20, s2.id, 'https://i.ibb.co/LdqjWMGL/Affiche-A3-Saa-S.png'),
            ('Brainstorming Session', 'Session de brainstorming stratégique 2h', 'service', 15000, 999, s1.id, 'https://i.ibb.co/xS5k3rxH/Brainstorming-Saa-S.png'),
            ('Casquette Coalition 509', 'Casquette brodée logo officiel', 'textile', 1500, 30, s1.id, 'https://i.ibb.co/DP6hYrPx/Casquettes-Saa-S.png'),
            ('Flyers A5 (lot 500)', 'Flyers recto/verso couleur', 'imprimerie', 2000, 100, s2.id, 'https://i.ibb.co/1fgqRWQm/Flyers-Saa-S.png'),
            ('Pack Hôtel Électoral', 'Réservation hôtel + transport pour équipe', 'service', 75000, 50, s1.id, 'https://i.ibb.co/8DcPN4w9/H-tel-Saa-S.png'),
            ('Pack Locomotion', 'Location véhicule + carburant journée', 'service', 45000, 30, s1.id, 'https://i.ibb.co/jPPNBQ3T/Locomotion-Saa-S.png'),
            ('Personal Branding', 'Kit photo + CV politique + réseaux', 'service', 25000, 100, s2.id, 'https://i.ibb.co/ynLW4hpC/Personnal-Branding-Saa-S.png'),
            ('Podcast Campagne', 'Production podcast 3 épisodes', 'service', 35000, 20, s2.id, 'https://i.ibb.co/vbdGJqr/Podcast-Saa-S.png'),
            ('Pack Restaurant', 'Traiteur 50 personnes + mobilier', 'service', 125000, 10, s1.id, 'https://i.ibb.co/ZzHFc5H9/Restaurant-Saa-S.png'),
            ('T-Shirt Coalition 509', 'T-shirt officiel 100% coton', 'textile', 2500, 50, s1.id, 'https://i.ibb.co/QFsDrWqZ/T-Shirts-Saa-S.png'),
        ]
        for name, desc, cat, price, stock, supp_id, img in products_data:
            db.session.add(Product(name=name, description=desc, category=cat, price=price, stock_quantity=stock, supplier_id=supp_id, status='active', image_url=img))
        db.session.commit()

        return jsonify({'status':'success','message':'Données de test injectées — 9 pilotes, 4 campagnes INACTIVE, 0 commande, stats bot conservées'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'status':'error','message':str(e)}), 500

# ============================================================
# BLUEPRINT : V1 (legacy compat)
# ============================================================
v1_bp = Blueprint('v1', __name__, url_prefix='/api/v1')

@v1_bp.route('/auth/login', methods=['POST'])
def v1_login(): return login()

@v1_bp.route('/auth/register', methods=['POST'])
def v1_register(): return register()

@v1_bp.route('/auth/me', methods=['GET'])
@token_required
def v1_me(): return me()

@v1_bp.route('/auth/verify-bot-token', methods=['POST'])
def v1_verify_bot_token(): return verify_bot_token()

@v1_bp.route('/dashboard/stats', methods=['GET'])
@token_required
def v1_dashboard_stats():
    try:
        total_users = User.query.count(); total_campaigns = Campaign.query.filter_by(status='active').count(); total_orders = Order.query.count()
        pending_orders = Order.query.filter_by(payment_status='pending').count()
        paid_orders = Order.query.filter_by(payment_status='paid').count()
        total_revenue = db.session.query(db.func.sum(Order.total_amount)).filter_by(payment_status='paid').scalar() or 0
        total_products = Product.query.count(); low_stock = Product.query.filter(Product.stock_quantity <= 5).count()
        total_suppliers = Supplier.query.count(); total_invoices = Invoice.query.count()
        return jsonify({'total_users':total_users,'total_campaigns':total_campaigns,'total_orders':total_orders,'pending_orders':pending_orders,'paid_orders':paid_orders,'total_revenue':float(total_revenue),'total_groups':0,'pending_withdrawals':0,'total_products':total_products,'low_stock':low_stock,'total_suppliers':total_suppliers,'total_invoices':total_invoices})
    except Exception as e:
        db.session.rollback()
        import traceback
        traceback.print_exc()
        return jsonify({'total_users':0,'total_campaigns':0,'total_orders':0,'pending_orders':0,'paid_orders':0,'total_revenue':0,'total_groups':0,'pending_withdrawals':0,'total_products':0,'low_stock':0,'total_suppliers':0,'total_invoices':0})

@v1_bp.route('/campaigns', methods=['GET'])
@token_required
def v1_list_campaigns(): return list_campaigns()

@v1_bp.route('/campaigns', methods=['POST'])
@token_required
def v1_create_campaign(): return create_campaign()

@v1_bp.route('/users', methods=['GET'])
@token_required
def v1_list_users(): return list_users()

@v1_bp.route('/orders', methods=['GET'])
@token_required
def v1_list_orders(): return list_orders()

@v1_bp.route('/payments/init', methods=['POST'])
@token_required
def v1_payments_init(): return pay_order()

@v1_bp.route('/payments/confirm', methods=['POST'])
@token_required
def v1_payments_confirm():
    data = request.get_json() or {}
    return jsonify({'ok':True,'status':'confirmed','payment_id':data.get('payment_id')})

@v1_bp.route('/export/users', methods=['GET'])
@token_required
def v1_export_users():
    import csv, io
    output = io.StringIO(); writer = csv.writer(output)
    writer.writerow(['ID','Phone','Nom','Prenom','Email','Role','Region','Commune'])
    for u in User.query.all(): writer.writerow([u.id,u.phone,u.last_name,u.first_name,u.email,u.role,u.region,u.commune])
    output.seek(0)
    from flask import Response
    return Response(output.getvalue(), mimetype='text/csv', headers={'Content-Disposition':'attachment; filename=users.csv'})

@v1_bp.route('/export/orders', methods=['GET'])
@token_required
def v1_export_orders():
    import csv, io
    output = io.StringIO(); writer = csv.writer(output)
    writer.writerow(['ID','Numero','Montant','Statut','Paiement','Region','Commune'])
    for o in Order.query.all(): writer.writerow([o.id,o.order_number,o.total_amount,o.status,o.payment_status,o.region,o.commune])
    output.seek(0)
    from flask import Response
    return Response(output.getvalue(), mimetype='text/csv', headers={'Content-Disposition':'attachment; filename=orders.csv'})

@v1_bp.route('/export/campaigns', methods=['GET'])
@token_required
def v1_export_campaigns():
    import csv, io
    output = io.StringIO(); writer = csv.writer(output)
    writer.writerow(['ID','Nom','Region','Commune','Statut','Date'])
    for c in Campaign.query.all(): writer.writerow([c.id,c.name,c.region,c.commune,c.status,c.election_date])
    output.seek(0)
    from flask import Response
    return Response(output.getvalue(), mimetype='text/csv', headers={'Content-Disposition':'attachment; filename=campaigns.csv'})

@v1_bp.route('/bot/stats', methods=['GET'])
def v1_bot_stats(): return jsonify(build_bot_stats_response())

@v1_bp.route('/bot/stats/history', methods=['GET'])
@token_required
def v1_bot_stats_history(): return bot_stats_history()

# ============================================================
# REGISTREMENT BLUEPRINTS
# ============================================================
app.register_blueprint(auth_bp)
app.register_blueprint(users_bp)
app.register_blueprint(campaigns_bp)
app.register_blueprint(orders_bp)
app.register_blueprint(stats_bp)
app.register_blueprint(bot_bp)
app.register_blueprint(init_bp)
app.register_blueprint(seed_bp)
app.register_blueprint(v1_bp)
app.register_blueprint(shop_bp)

@app.route('/')
def index():
    return jsonify({'service':'Coalition 509 API','version':'2.9.5','status':'ok','modules':['auth','campaigns','users','orders','bot','shop']})

def auto_migrate():
    try:
        with db.engine.connect() as conn:
            result = conn.execute(db.text("SELECT column_name FROM information_schema.columns WHERE table_name='bot_stats' AND column_name='source'"))
            if not result.fetchone():
                conn.execute(db.text("ALTER TABLE bot_stats ADD COLUMN source VARCHAR(50) DEFAULT 'unknown'"))
                conn.commit()
                print("[MIGRATE] Colonne 'source' ajoutee a bot_stats")
            else:
                print("[MIGRATE] Colonne 'source' deja presente")

            result2 = conn.execute(db.text("SELECT column_name FROM information_schema.columns WHERE table_name='deliveries' AND column_name='supplier_id'"))
            if not result2.fetchone():
                conn.execute(db.text("ALTER TABLE deliveries ADD COLUMN supplier_id INTEGER"))
                conn.commit()
                print("[MIGRATE] Colonne 'supplier_id' ajoutee a deliveries")
            else:
                print("[MIGRATE] Colonne 'supplier_id' deja presente")

            result3 = conn.execute(db.text("SELECT column_name FROM information_schema.columns WHERE table_name='deliveries' AND column_name='delivery_person'"))
            if not result3.fetchone():
                conn.execute(db.text("ALTER TABLE deliveries ADD COLUMN delivery_person VARCHAR(100)"))
                conn.commit()
                print("[MIGRATE] Colonne 'delivery_person' ajoutee a deliveries")
            else:
                print("[MIGRATE] Colonne 'delivery_person' deja presente")

            result4 = conn.execute(db.text("SELECT column_name FROM information_schema.columns WHERE table_name='deliveries' AND column_name='delivery_phone'"))
            if not result4.fetchone():
                conn.execute(db.text("ALTER TABLE deliveries ADD COLUMN delivery_phone VARCHAR(20)"))
                conn.commit()
                print("[MIGRATE] Colonne 'delivery_phone' ajoutee a deliveries")
            else:
                print("[MIGRATE] Colonne 'delivery_phone' deja presente")
    except Exception as e:
        print(f"[MIGRATE] {e}")

with app.app_context():
    db.create_all()
    print("[BOOT] Tables verifiees/creees v2.9.5")
    auto_migrate()

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
