"""
Coalition 509 API — Backend v2.11.0
v2.11.0 (15/10/2026) — CANDIDATS TÊTES DE LISTE :
  1. POST /api/users/promote (Gestionnaire seul) : un compte devient « Candidat Tête de liste » (rôle admin)
     avec sa candidature (liste / circonscription) et une confirmation explicite → accès à la Boutique.
  2. POST /api/users/demote (Gestionnaire seul) : retrait du statut, motif obligatoire ; effet immédiat
     (le rôle est relu à chaque requête). Impossible sur son propre compte ou sur un superadmin.
  3. GET /api/users/role-history (Gestionnaire seul) : journal des promotions et retraits (table role_changes).
  4. Annuaire des utilisateurs (GET /api/users, /api/v1/users) : réservé aux Candidats et au Gestionnaire
     (un citoyen pouvait lire tous les numéros) ; filtres role= et search=, « limit » accepté (max 200).
     Export CSV /api/v1/export/users : Gestionnaire seul. Export CSV des commandes : chacun les siennes,
     le Gestionnaire toutes (il livrait toutes les commandes à n'importe quel compte connecté).
  5. Migration automatique : colonnes candidature, promoted_at, promoted_by sur users.
  6. COMPTES OFFICIELS VoteConnect inscrits dans le code (COMPTES_OFFICIELS) : 07 07 78 66 14, 07 67 56 09 08,
     07 87 10 21 90, 05 05 76 17 84 — Admin (Candidat Tête de liste) ET Gestionnaire, quel que soit le format saisi
     (0707…, +225 07…, 00225 07…). Rôle admin appliqué au démarrage, à l'inscription, à la connexion et au lien du bot.
     Leur statut ne peut pas être retiré depuis le tableau de bord. GESTIONNAIRES_BOUTIQUE (Render) AJOUTE des délégués.
  7. Comptes de DÉMONSTRATION (00225 07 07 77 77 01 à 09, PIN 1234 public dans le code) : désactivés au démarrage
     (rôle user, statut inactif) ; /api/seed les recrée inactifs et ne supprime plus les comptes officiels.
  8. Un compte désactivé perd immédiatement ses sessions ouvertes (le jeton est refusé).
  9. Connexion / inscription / lien du bot : le compte est retrouvé quel que soit le format du numéro
     (un compte créé en « 07… » se connecte aussi en « +225 07… », et ne peut plus être créé en double).
v2.10.0 (15/10/2026) — BOUTIQUE SÉCURISÉE (paiement Wave vérifié) :
  1. Boutique réservée aux Candidats Têtes de liste (rôle admin) et aux Gestionnaires VoteConnect
     (numéro listé dans GESTIONNAIRES_BOUTIQUE sur Render, ou rôle superadmin). Un citoyen (rôle user)
     n'a plus accès aux routes /api/shop/*, même en appelant l'API directement.
  2. Paiement Wave sur le marchand FORMATION (WAVE_MARCHAND_FORMATION, par défaut M_ci_QlW5ke-hYGbA) :
     commande → lien Wave (montant pré-rempli) → RÉFÉRENCE Wave obligatoire (POST /api/shop/orders/declare-payment,
     6 à 30 caractères A-Z0-9, unique) → validation ou rejet par le Gestionnaire (POST /api/shop/orders/validate-payment)
     après contrôle dans l'application Wave.
  3. À la validation seulement : stock retiré, facture « payée », livraison lancée (awaiting_payment → pending).
     Vérification du stock à l'ajout au panier, à la commande et à la validation.
  4. Portes fermées : /api/orders/pay, /api/v1/payments/init et /api/v1/payments/confirm répondent 410 (ils marquaient
     une commande « payée » sans argent, pour n'importe quel utilisateur connecté). orders/update et invoices/update ne
     peuvent plus mettre « payé ». Une commande payée ou déclarée ne se supprime plus.
  5. Chaque Candidat ne voit que ses commandes, factures et livraisons ; le Gestionnaire voit tout.
     Catalogue, fournisseurs, stocks et livraisons : Gestionnaire seul.
  6. Annulation d'une commande non payée : POST /api/shop/orders/cancel.
  7. Profil (login, me, lien du bot) : champs « gestionnaire » et « acheteur » pour le tableau de bord.
  8. Migration automatique : colonnes wave_reference, payment_declared_at, payment_validated_at,
     payment_validated_by, payment_note sur orders.
v2.9.8 (02/10/2026) — PLACE DE MARCHÉ :
  1. Catalogue de démonstration aligné sur les prix réels en ligne (10 produits, 5 000 à 500 000 FCFA).
  2. Guichet GET /api/stats-partenaires (en-tête X-Stats-Key = STATS_KEY) pour le Hub Partenaires :
     ventes payées par jour, volume brut et revenu net VoteConnect.
     Revenu net : 100 % pour les prestations vendues en propre (VC_PRODUITS_PROPRES),
     COMMISSION_PCT % (10 par défaut) pour les produits livrés par les fournisseurs.
v2.9.7 (29/09/2026) — SÉCURITÉ :
  1. Jeton de session signé (itsdangerous, 30 jours) au lieu du numéro de téléphone.
     Avant : connaître un numéro suffisait pour agir au nom de son titulaire (y compris admin).
  2. Lien de connexion du Bot Challenger (bot_auth) réellement vérifié (HMAC, validité 30 min).
     Avant : la signature n'était jamais contrôlée.
  3. /api/init-db et /api/seed (effacement de la base) protégés par ADMIN_RESET_KEY.
     Avant : une simple visite de l'URL effaçait toutes les données.
Module SHOP intégré : Produits, Panier, Commandes, Fournisseurs, Livraisons, Paiements, Factures, Stocks
Fix : teardown session + rollback stats + SSL EOF robustness
RÈGLE D'OR : pas de chevrons <> dans les routes Flask — query params uniquement
"""

import os, uuid, hashlib, hmac, datetime, time, re
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from functools import wraps
from flask import Flask, request, jsonify, Blueprint
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'postgresql://localhost/coalition509')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'coalition509-dev-secret')
if app.config['SECRET_KEY'] == 'coalition509-dev-secret':
    print("[SECURITE] ⚠️ SECRET_KEY par défaut (publique sur GitHub) — définissez SECRET_KEY dans Render → Environment")
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
    # v2.11.0 — Candidat Tête de liste
    candidature = db.Column(db.String(150))          # ex. « Coalition Bélier — Conseil Régional du Bélier »
    promoted_at = db.Column(db.DateTime)
    promoted_by = db.Column(db.Integer)

class RoleChange(db.Model):
    # v2.11.0 — journal des promotions / retraits du statut Candidat Tête de liste
    __tablename__ = 'role_changes'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, index=True, nullable=False)
    old_role = db.Column(db.String(20))
    new_role = db.Column(db.String(20))
    candidature = db.Column(db.String(150))
    motif = db.Column(db.Text)
    by_user_id = db.Column(db.Integer)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class Campaign(db.Model):
    __tablename__ = 'campaigns'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    election_date = db.Column(db.Date)
    election_type = db.Column(db.String(50))
    region = db.Column(db.String(50))
    commune = db.Column(db.String(50))
    status = db.Column(db.String(20), default='active')
    price = db.Column(db.Numeric(12, 2), default=0)
    pricing_model = db.Column(db.String(20), default='forfait')
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
    # v2.10.0 — paiement Wave vérifié
    wave_reference = db.Column(db.String(40), index=True)
    payment_declared_at = db.Column(db.DateTime)
    payment_validated_at = db.Column(db.DateTime)
    payment_validated_by = db.Column(db.Integer)
    payment_note = db.Column(db.Text)

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
# ── Jetons de session signés (v2.9.7) ──────────────────────
SESSION_MAX_AGE = int(os.environ.get('SESSION_MAX_AGE', 30 * 24 * 3600))  # 30 jours
def _session_serializer():
    return URLSafeTimedSerializer(app.config['SECRET_KEY'], salt='c509-session-v1')
def make_session_token(user):
    return _session_serializer().dumps({'u': user.id, 'p': user.phone})
def user_from_session_token(token):
    """Renvoie l'utilisateur si le jeton est authentique et non expiré, sinon None."""
    try:
        data = _session_serializer().loads(token, max_age=SESSION_MAX_AGE)
    except (BadSignature, SignatureExpired):
        return None
    if not isinstance(data, dict): return None
    user = db.session.get(User, data.get('u'))
    if not user or user.phone != data.get('p'): return None
    if (user.status or 'active') != 'active': return None   # v2.11.0 : compte désactivé → sessions refusées
    return user

# ── Liens de connexion du Bot Challenger (v2.9.7) ─────────
# Format inchangé pour le bot : "<téléphone>|<32 hex>". La signature dépend
# d'une fenêtre de 10 minutes ; un lien reste valable 3 fenêtres (≤ 30 min).
BOT_LINK_WINDOW = 600
BOT_LINK_WINDOWS_OK = 3
def _bot_link_sig(phone, window):
    msg = f"bot-link|{phone}|{window}".encode()
    return hmac.new(app.config['SECRET_KEY'].encode(), msg, hashlib.sha256).hexdigest()[:32]
def make_bot_link_token(phone):
    return f"{phone}|{_bot_link_sig(phone, int(time.time() // BOT_LINK_WINDOW))}"
def verify_bot_link_token(token):
    """Renvoie le téléphone normalisé si le lien est authentique et récent, sinon None."""
    if not token or '|' not in token: return None
    raw_phone, sig = token.rsplit('|', 1)
    phone = normaliser_tel(raw_phone)
    if not phone or len(sig) != 32: return None
    now_w = int(time.time() // BOT_LINK_WINDOW)
    for w in range(now_w, now_w - BOT_LINK_WINDOWS_OK, -1):
        if hmac.compare_digest(sig, _bot_link_sig(phone, w)):
            return phone
    return None

# ── Protection des routes d'effacement (v2.9.7) ───────────
def reset_key_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        expected = os.environ.get('ADMIN_RESET_KEY', '')
        given = request.headers.get('X-Admin-Reset-Key', '') or request.args.get('key', '')
        if len(expected) < 16 or not hmac.compare_digest(given, expected):
            return jsonify({'status':'error','message':'Opération désactivée ou clé invalide'}), 403
        return f(*args, **kwargs)
    return decorated

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
            user = user_from_session_token(token)
            if not user:
                return jsonify({'status':'error','message':'Session invalide ou expirée — reconnectez-vous'}), 401
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

# ── v2.10.0 : Boutique — accès et paiement Wave ─────────────
def cle_tel(t):
    # Clé de comparaison : les 10 chiffres du numéro ivoirien, quel que soit le format (0707…, +225 07…, 00225 07…)
    d = re.sub(r'\D', '', str(t or ''))
    if d.startswith('00'): d = d[2:]
    if d.startswith('225') and len(d) == 13: d = d[3:]
    return d

# Comptes officiels VoteConnect — Admin (Candidat Tête de liste) ET Gestionnaire de la Boutique
COMPTES_OFFICIELS = ('0707786614', '0767560908', '0787102190', '0505761784')
# Anciens comptes de démonstration (PIN 1234 public) : neutralisés au démarrage
COMPTES_DEMO = tuple(f'07077777{i:02d}' for i in range(1, 10))
GESTIONNAIRES_BOUTIQUE = {cle_tel(x) for x in COMPTES_OFFICIELS} | {cle_tel(x) for x in os.environ.get('GESTIONNAIRES_BOUTIQUE', '').split(',') if cle_tel(x)}
WAVE_MARCHAND_FORMATION = (os.environ.get('WAVE_MARCHAND_FORMATION', 'M_ci_QlW5ke-hYGbA') or 'M_ci_QlW5ke-hYGbA').strip()
print(f"[BOUTIQUE] {len(GESTIONNAIRES_BOUTIQUE)} Gestionnaire(s) : {len(COMPTES_OFFICIELS)} compte(s) officiel(s) + délégués Render")

def est_gestionnaire(u):
    # Gestionnaire VoteConnect : compte officiel (COMPTES_OFFICIELS), délégué listé dans GESTIONNAIRES_BOUTIQUE (Render), ou superadmin.
    if not u: return False
    return u.role == 'superadmin' or cle_tel(u.phone) in GESTIONNAIRES_BOUTIQUE

def est_acheteur(u):
    # Candidats Têtes de liste (rôle admin) et Gestionnaires
    return bool(u) and (u.role in ('admin', 'superadmin') or est_gestionnaire(u))

def boutique_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not hasattr(request, 'current_user') or not est_acheteur(request.current_user):
            return jsonify({'status':'error','message':'Boutique réservée aux Candidats Têtes de liste (administrateurs).'}), 403
        return f(*args, **kwargs)
    return decorated

def gestionnaire_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not hasattr(request, 'current_user') or not est_gestionnaire(request.current_user):
            return jsonify({'status':'error','message':'Réservé au Gestionnaire de la Boutique (VoteConnect).'}), 403
        return f(*args, **kwargs)
    return decorated

def lien_wave(montant):
    try: m = int(round(float(montant or 0)))
    except (TypeError, ValueError): m = 0
    return f"https://pay.wave.com/m/{WAVE_MARCHAND_FORMATION}/c/ci/?amount={m}"

def norm_ref_wave(r):
    return re.sub(r'[^A-Z0-9]', '', str(r if r is not None else '').upper())

def user_json(u):
    return {'id':u.id,'phone':u.phone,'first_name':u.first_name,'last_name':u.last_name,'email':u.email,'role':u.role,
            'region':u.region,'commune':u.commune,'profile_type':u.profile_type,'ngd_id':u.ngd_id,
            'acheteur':est_acheteur(u),'gestionnaire':est_gestionnaire(u),'candidature':u.candidature}

def trouver_par_tel(phone):
    """Compte correspondant au numéro, quel que soit le format enregistré (0707…, 002250707…, +2250707…)."""
    u = User.query.filter_by(phone=phone).first() if phone else None
    if u: return u
    k = cle_tel(phone)
    if len(k) != 10: return None
    return User.query.filter(User.phone.in_([k, '00225' + k, '225' + k, '+225' + k])).first()

def est_officiel(u):
    return bool(u) and cle_tel(u.phone) in {cle_tel(x) for x in COMPTES_OFFICIELS}

def aligner_compte_officiel(u):
    """Compte officiel VoteConnect : rôle admin garanti (sans commit). Renvoie True si modifié."""
    if not est_officiel(u) or u.role in ('admin', 'superadmin'): return False
    ancien = u.role or 'user'
    u.role = 'admin'; u.candidature = u.candidature or 'VoteConnect — Compte officiel'
    u.promoted_at = datetime.datetime.utcnow()
    if u.id: db.session.add(RoleChange(user_id=u.id, old_role=ancien, new_role='admin', candidature=u.candidature,
                                       motif='Compte officiel VoteConnect (Admin & Gestionnaire)', by_user_id=None))
    return True

def preparer_comptes():
    """Démarrage : comptes officiels → admin ; comptes de démonstration → désactivés."""
    demo = {cle_tel(x) for x in COMPTES_DEMO}
    n_off = n_demo = 0
    for u in User.query.all():
        if aligner_compte_officiel(u): n_off += 1
        elif cle_tel(u.phone) in demo and (u.status != 'inactive' or u.role != 'user'):
            if u.role == 'admin':
                db.session.add(RoleChange(user_id=u.id, old_role='admin', new_role='user', candidature=u.candidature,
                                          motif='Compte de démonstration désactivé', by_user_id=None))
            u.role = 'user'; u.status = 'inactive'; u.candidature = None; n_demo += 1
    db.session.commit()
    print(f"[COMPTES] {n_off} compte(s) officiel(s) passé(s) Admin — {n_demo} compte(s) de démonstration désactivé(s)")

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
    user = trouver_par_tel(phone)
    if not user or user.pin_hash != hash_pin(pin):
        return jsonify({'status':'error','message':'Identifiants invalides'}), 401
    if user.status != 'active':
        return jsonify({'status':'error','message':'Compte inactif'}), 403
    if aligner_compte_officiel(user): db.session.commit()
    tok = make_session_token(user)
    return jsonify({'status':'success','token':tok,'access_token':tok,'user':user_json(user)})

@auth_bp.route('/register', methods=['POST'])
def register():
    data = request.get_json() or {}
    phone = normaliser_tel(data.get('phone', ''))
    pin = data.get('pin', '').strip()
    first_name = data.get('first_name', '').strip()
    last_name = data.get('last_name', '').strip()
    if not phone or not pin or not first_name or not last_name:
        return jsonify({'status':'error','message':'Champs obligatoires manquants'}), 400
    if trouver_par_tel(phone):
        return jsonify({'status':'error','message':'Telephone deja utilise'}), 409
    user = User(phone=phone, pin_hash=hash_pin(pin), first_name=first_name, last_name=last_name,
                email=data.get('email',''), role='user', status='active',
                region=data.get('region',''), commune=data.get('commune',''),
                profile_type=data.get('profile_type','Animateur NGD'), ngd_id=generate_ngd_id())
    db.session.add(user); db.session.commit()
    if aligner_compte_officiel(user): db.session.commit()
    tok = make_session_token(user)
    return jsonify({'status':'success','token':tok,'access_token':tok,'id':user.id,'ngd_id':user.ngd_id,'user':user_json(user)}), 201

@auth_bp.route('/me', methods=['GET'])
@token_required
def me():
    u = request.current_user
    return jsonify({'status':'success','user':user_json(u)})

@auth_bp.route('/verify-bot-token', methods=['POST'])
def verify_bot_token():
    data = request.get_json() or {}
    bot_token = data.get('token', '')
    if not bot_token:
        return jsonify({'ok':False,'error':'Token manquant'}), 400
    try:
        phone = verify_bot_link_token(bot_token)
        if not phone:
            return jsonify({'ok':False,'error':'Lien de connexion invalide ou expiré (validité 30 min) — rouvrez « Élections » dans le bot'})
        user = trouver_par_tel(phone)
        if user and user.status != 'active':
            return jsonify({'ok':False,'error':'Compte inactif — contactez un administrateur'})
        if user:
            if aligner_compte_officiel(user): db.session.commit()
            return jsonify({'ok':True,'access_token':make_session_token(user),'user':user_json(user)})
        else:
            return jsonify({'ok':True,'needs_registration':True,'phone':phone})
    except Exception as e:
        db.session.rollback()
        return jsonify({'ok':False,'error':str(e)}), 400

# ============================================================
# BLUEPRINT : USERS
# ============================================================
users_bp = Blueprint('users', __name__, url_prefix='/api/users')

def annuaire_required(f):
    # v2.11.0 — annuaire réservé aux Candidats Têtes de liste et au Gestionnaire (un citoyen lisait tous les numéros)
    @wraps(f)
    def decorated(*args, **kwargs):
        if not hasattr(request, 'current_user') or not est_acheteur(request.current_user):
            return jsonify({'status':'error','message':'Annuaire réservé aux Candidats Têtes de liste et au Gestionnaire.'}), 403
        return f(*args, **kwargs)
    return decorated

def nom_complet(u):
    return (' '.join(x for x in ((u.first_name or '').strip(), (u.last_name or '').strip()) if x) or u.phone) if u else '—'

def user_list_json(u):
    return {'id':u.id,'phone':u.phone,'first_name':u.first_name,'last_name':u.last_name,'email':u.email,'role':u.role,'status':u.status,
            'region':u.region,'commune':u.commune,'profile_type':u.profile_type,'ngd_id':u.ngd_id,
            'created_at':u.created_at.isoformat() if u.created_at else None,
            'tete_de_liste':u.role == 'admin','gestionnaire':est_gestionnaire(u),
            'candidature':u.candidature,'promoted_at':u.promoted_at.isoformat() if u.promoted_at else None}

@users_bp.route('', methods=['GET'])
@token_required
@annuaire_required
def list_users():
    page = max(request.args.get('page', 1, type=int) or 1, 1)
    per_page = request.args.get('per_page', type=int) or request.args.get('limit', type=int) or 10
    per_page = min(max(per_page, 1), 200)
    search = request.args.get('search', '').strip()
    role = request.args.get('role', '').strip().lower()
    q = User.query.order_by(User.created_at.desc())
    if search:
        q = q.filter(db.or_(
            User.first_name.ilike(f'%{search}%'),
            User.last_name.ilike(f'%{search}%'),
            User.phone.ilike(f'%{search}%'),
            User.candidature.ilike(f'%{search}%')
        ))
    if role in ('admin', 'user', 'superadmin'):
        q = q.filter(User.role == role)
    total = q.count()
    users = q.offset((page-1)*per_page).limit(per_page).all()
    return jsonify({'status':'success','page':page,'per_page':per_page,'total':total,'users':[user_list_json(u) for u in users]})

def _utilisateur_cible(data):
    try: uid = int(data.get('user_id') or 0)
    except (TypeError, ValueError): uid = 0
    return db.session.get(User, uid) if uid > 0 else None

@users_bp.route('/promote', methods=['POST'])
@token_required
@gestionnaire_required
def promote_user():
    # v2.11.0 — « Promouvoir Candidat Tête de liste » : rôle admin → accès Boutique
    data = request.get_json() or {}
    me = request.current_user
    u = _utilisateur_cible(data)
    if not u: return jsonify({'status':'error','message':'Utilisateur introuvable'}), 404
    if u.role == 'superadmin': return jsonify({'status':'error','message':'Compte superadmin : non modifiable ici.'}), 409
    if (u.status or 'active') != 'active': return jsonify({'status':'error','message':"Ce compte n'est pas actif."}), 409
    cand = ' '.join(str(data.get('candidature') or '').split())
    if not (3 <= len(cand) <= 150):
        return jsonify({'status':'error','message':'Indiquez la liste et la circonscription du Candidat (3 à 150 caractères).'}), 400
    if data.get('confirme') is not True:
        return jsonify({'status':'error','message':'Confirmez que cette personne est Candidat Tête de liste officiel.'}), 400
    ancien = u.role or 'user'
    if ancien == 'admin' and (u.candidature or '') == cand:
        return jsonify({'status':'error','message':f"{nom_complet(u)} est déjà Candidat Tête de liste ({cand})."}), 409
    u.role = 'admin'; u.candidature = cand
    if ancien != 'admin': u.promoted_at = datetime.datetime.utcnow(); u.promoted_by = me.id
    db.session.add(RoleChange(user_id=u.id, old_role=ancien, new_role='admin', candidature=cand,
                              motif=('Promotion' if ancien != 'admin' else 'Mise à jour de la candidature'), by_user_id=me.id))
    db.session.commit()
    msg = (f"{nom_complet(u)} est désormais Candidat Tête de liste — la Boutique lui est ouverte." if ancien != 'admin'
           else f"Candidature de {nom_complet(u)} mise à jour.")
    return jsonify({'status':'success','message':msg,'user':user_list_json(u)})

@users_bp.route('/demote', methods=['POST'])
@token_required
@gestionnaire_required
def demote_user():
    # v2.11.0 — retrait du statut Candidat Tête de liste (retour « Citoyen en formation »), effet immédiat
    data = request.get_json() or {}
    me = request.current_user
    u = _utilisateur_cible(data)
    if not u: return jsonify({'status':'error','message':'Utilisateur introuvable'}), 404
    if u.id == me.id: return jsonify({'status':'error','message':'Vous ne pouvez pas retirer votre propre statut.'}), 409
    if u.role != 'admin': return jsonify({'status':'error','message':f"{nom_complet(u)} n'est pas Candidat Tête de liste."}), 409
    if est_officiel(u): return jsonify({'status':'error','message':f"{nom_complet(u)} est un compte officiel VoteConnect : son statut ne se retire pas ici."}), 409
    motif = ' '.join(str(data.get('motif') or '').split())
    if not (3 <= len(motif) <= 300):
        return jsonify({'status':'error','message':'Indiquez le motif du retrait (3 à 300 caractères).'}), 400
    a_verifier = Order.query.filter_by(user_id=u.id, payment_status='declared').count()
    db.session.add(RoleChange(user_id=u.id, old_role='admin', new_role='user', candidature=u.candidature, motif=motif, by_user_id=me.id))
    u.role = 'user'; u.candidature = None
    db.session.commit()
    msg = f"{nom_complet(u)} redevient Citoyen en formation — la Boutique lui est fermée."
    if a_verifier: msg += f" {a_verifier} paiement(s) déclaré(s) restent à vérifier dans Boutique → Paiements."
    if est_gestionnaire(u): msg += " Attention : son numéro figure dans GESTIONNAIRES_BOUTIQUE (Render), il garde donc l'accès Gestionnaire."
    return jsonify({'status':'success','message':msg,'user':user_list_json(u)})

@users_bp.route('/role-history', methods=['GET'])
@token_required
@gestionnaire_required
def role_history():
    rows = RoleChange.query.order_by(RoleChange.created_at.desc(), RoleChange.id.desc()).limit(100).all()
    ids = {r.user_id for r in rows} | {r.by_user_id for r in rows if r.by_user_id}
    noms = {u.id: nom_complet(u) for u in (User.query.filter(User.id.in_(ids)).all() if ids else [])}
    return jsonify({'status':'success','history':[{'id':r.id,'user_id':r.user_id,'user':noms.get(r.user_id, f'#{r.user_id}'),
        'action':'promotion' if r.new_role == 'admin' and r.old_role != 'admin' else ('mise_a_jour' if r.new_role == 'admin' else 'retrait'),
        'candidature':r.candidature,'motif':r.motif,'par':noms.get(r.by_user_id, '—'),
        'created_at':r.created_at.isoformat() if r.created_at else None} for r in rows]})

# ============================================================
# BLUEPRINT : CAMPAIGNS
# ============================================================
campaigns_bp = Blueprint('campaigns', __name__, url_prefix='/api/campaigns')

@campaigns_bp.route('', methods=['GET'])
@token_required
def list_campaigns():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    status = request.args.get('status', '').strip()
    search = request.args.get('search', '').strip()
    region = request.args.get('region', '').strip()
    q = Campaign.query.order_by(Campaign.created_at.desc())
    if status:
        q = q.filter_by(status=status)
    if region:
        q = q.filter(Campaign.region.ilike(f'%{region}%'))
    if search:
        q = q.filter(db.or_(
            Campaign.name.ilike(f'%{search}%'),
            Campaign.description.ilike(f'%{search}%')
        ))
    total = q.count()
    camps = q.offset((page-1)*per_page).limit(per_page).all()
    return jsonify({'status':'success','page':page,'per_page':per_page,'total':total,'campaigns':[{'id':c.id,'name':c.name,'description':c.description,'election_date':str(c.election_date) if c.election_date else None,'election_type':c.election_type,'region':c.region,'commune':c.commune,'status':c.status,'price':float(c.price) if c.price else 0,'pricing_model':c.pricing_model,'created_by':c.created_by,'created_at':c.created_at.isoformat() if c.created_at else None} for c in camps]})

@campaigns_bp.route('', methods=['POST'])
@token_required
def create_campaign():
    data = request.get_json() or {}
    c = Campaign(
        name=data.get('name',''),
        description=data.get('description',''),
        election_date=datetime.datetime.strptime(data['election_date'],'%Y-%m-%d').date() if data.get('election_date') else None,
        election_type=data.get('election_type',''),
        region=data.get('region',''),
        commune=data.get('commune',''),
        price=data.get('price',0),
        pricing_model=data.get('pricing_model','forfait'),
        created_by=request.current_user.id
    )
    db.session.add(c); db.session.commit()
    return jsonify({'status':'success','campaign':{'id':c.id,'name':c.name}}), 201

@campaigns_bp.route('/detail', methods=['GET'])
@token_required
def get_campaign():
    cid = request.args.get('id', type=int)
    if not cid: return jsonify({'status':'error','message':'id requis'}), 400
    c = Campaign.query.get(cid)
    if not c: return jsonify({'status':'error','message':'Campagne introuvable'}), 404
    return jsonify({'status':'success','campaign':{'id':c.id,'name':c.name,'description':c.description,'election_date':str(c.election_date) if c.election_date else None,'election_type':c.election_type,'region':c.region,'commune':c.commune,'status':c.status,'price':float(c.price) if c.price else 0,'pricing_model':c.pricing_model,'created_by':c.created_by,'created_at':c.created_at.isoformat() if c.created_at else None}})

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
    c.election_type = data.get('election_type', c.election_type)
    c.region = data.get('region', c.region); c.commune = data.get('commune', c.commune); c.status = data.get('status', c.status)
    c.price = data.get('price', c.price)
    c.pricing_model = data.get('pricing_model', c.pricing_model)
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
    if not est_gestionnaire(request.current_user): q = q.filter(Order.user_id == request.current_user.id)   # v2.10.0
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
    if not o or not (est_gestionnaire(request.current_user) or o.user_id == request.current_user.id):   # v2.10.0
        return jsonify({'status':'error','message':'Commande introuvable'}), 404
    u = User.query.get(o.user_id)
    items = OrderItem.query.filter_by(order_id=o.id).all()
    items_out = []
    for it in items:
        p = Product.query.get(it.product_id)
        items_out.append({'id':it.id,'product_id':it.product_id,'product_name':p.name if p else '—','quantity':it.quantity,'unit_price':float(it.unit_price),'total_price':float(it.total_price)})
    return jsonify({'status':'success','order':{'id':o.id,'order_number':o.order_number,'total_amount':float(o.total_amount) if o.total_amount else 0,'status':o.status,'payment_status':o.payment_status,'payment_method':o.payment_method,'region':o.region,'commune':o.commune,'created_at':o.created_at.isoformat() if o.created_at else None,'user':{'id':u.id,'phone':u.phone,'first_name':u.first_name,'last_name':u.last_name} if u else None,'items':items_out}})

PAIEMENT_FERME = {'status':'error','message':"Route fermée (v2.10.0) : payez par Wave puis saisissez la référence de la transaction (POST /api/shop/orders/declare-payment). Le paiement est validé par VoteConnect après contrôle."}

@orders_bp.route('/pay', methods=['POST'])
@token_required
def pay_order():
    # v2.10.0 — cette route marquait n'importe quelle commande « payée » sans aucun paiement : fermée.
    return jsonify(PAIEMENT_FERME), 410

# ============================================================
# BLUEPRINT : SHOP — v2.10.0 « Boutique sécurisée »
# • Boutique réservée aux Candidats Têtes de liste (rôle admin) et au(x)
#   Gestionnaire(s) VoteConnect.
# • Paiement : Wave, marchand Formation (WAVE_MARCHAND_FORMATION).
#   Commande → lien Wave → RÉFÉRENCE Wave obligatoire → validation par le
#   Gestionnaire après contrôle dans l'application Wave.
# • Le stock n'est retiré, la facture payée et la livraison lancée qu'à la
#   validation. Une référence Wave ne sert qu'une fois.
# • Catalogue, fournisseurs, stocks, livraisons, factures : Gestionnaire seul.
# ============================================================
shop_bp = Blueprint('shop', __name__, url_prefix='/api/shop')

STATUTS_LIVRAISON_OK = ('pending', 'processing', 'shipped', 'delivered')
STATUTS_COMMANDE_APRES_PAIEMENT = ('confirmed', 'processing', 'shipped', 'delivered', 'completed')

def _items_json(order_id):
    out = []
    for it in OrderItem.query.filter_by(order_id=order_id).all():
        p = db.session.get(Product, it.product_id)
        out.append({'id': it.id, 'product_id': it.product_id, 'product_name': p.name if p else '—', 'quantity': it.quantity,
                    'unit_price': float(it.unit_price or 0), 'total_price': float(it.total_price or 0)})
    return out

def _user_court(u):
    return {'id': u.id, 'phone': u.phone, 'first_name': u.first_name, 'last_name': u.last_name} if u else None

def order_json(o, details=False):
    u = db.session.get(User, o.user_id)
    d = {'id': o.id, 'order_number': o.order_number, 'user_id': o.user_id,
         'total_amount': float(o.total_amount) if o.total_amount else 0, 'status': o.status,
         'payment_status': o.payment_status, 'payment_method': o.payment_method,
         'wave_reference': o.wave_reference, 'payment_note': o.payment_note,
         'payment_declared_at': o.payment_declared_at.isoformat() if o.payment_declared_at else None,
         'payment_validated_at': o.payment_validated_at.isoformat() if o.payment_validated_at else None,
         'region': o.region, 'commune': o.commune,
         'created_at': o.created_at.isoformat() if o.created_at else None,
         'user': _user_court(u), 'items': _items_json(o.id),
         'wave_url': lien_wave(o.total_amount) if o.payment_status in ('pending', 'rejected') else None}
    if details:
        inv = Invoice.query.filter_by(order_id=o.id).first()
        d['invoice'] = {'id': inv.id, 'invoice_number': inv.invoice_number, 'amount': float(inv.amount or 0), 'status': inv.status,
                        'paid_at': inv.paid_at.isoformat() if inv.paid_at else None} if inv else None
        livs = []
        for dl in Delivery.query.filter_by(order_id=o.id).all():
            s = db.session.get(Supplier, dl.supplier_id) if dl.supplier_id else None
            livs.append({'id': dl.id, 'status': dl.status, 'tracking_number': dl.tracking_number,
                         'estimated_date': str(dl.estimated_date) if dl.estimated_date else None,
                         'delivered_at': dl.delivered_at.isoformat() if dl.delivered_at else None,
                         'supplier': {'id': s.id, 'name': s.name, 'phone': s.phone} if s else None,
                         'delivery_person': dl.delivery_person, 'delivery_phone': dl.delivery_phone,
                         'address': dl.address, 'notes': dl.notes})
        d['deliveries'] = livs
    return d

def _commande_visible(o):
    u = request.current_user
    return o is not None and (est_gestionnaire(u) or o.user_id == u.id)

def _ids_commandes_visibles():
    """None = toutes (Gestionnaire) ; sinon la liste des commandes de l'utilisateur."""
    u = request.current_user
    if est_gestionnaire(u): return None
    return [o.id for o in Order.query.with_entities(Order.id).filter_by(user_id=u.id).all()]

# ── Catalogue ──────────────────────────────────────────────
def _product_json(p):
    return {'id': p.id, 'name': p.name, 'description': p.description, 'category': p.category, 'price': float(p.price or 0),
            'stock_quantity': p.stock_quantity, 'supplier_id': p.supplier_id, 'status': p.status, 'image_url': p.image_url,
            'created_at': p.created_at.isoformat() if p.created_at else None}

@shop_bp.route('/products', methods=['GET'])
@token_required
@boutique_required
def shop_list_products():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    cat = request.args.get('category', '')
    search = request.args.get('search', '').strip()
    q = Product.query
    if not est_gestionnaire(request.current_user): q = q.filter(Product.status == 'active')
    if cat: q = q.filter_by(category=cat)
    if search: q = q.filter(Product.name.ilike(f'%{search}%'))
    q = q.order_by(Product.created_at.desc())
    total = q.count()
    products = q.offset((page-1)*per_page).limit(per_page).all()
    return jsonify({'status':'success','page':page,'per_page':per_page,'total':total,'products':[_product_json(p) for p in products]})

@shop_bp.route('/products', methods=['POST'])
@token_required
@gestionnaire_required
def shop_create_product():
    data = request.get_json() or {}
    if not str(data.get('name') or '').strip(): return jsonify({'status':'error','message':'Nom du produit requis'}), 400
    try: prix = float(data.get('price', 0) or 0)
    except (TypeError, ValueError): return jsonify({'status':'error','message':'Prix invalide'}), 400
    if prix < 0: return jsonify({'status':'error','message':'Prix invalide'}), 400
    p = Product(name=data.get('name',''), description=data.get('description',''), category=data.get('category','general'),
                price=prix, stock_quantity=int(data.get('stock_quantity', 0) or 0), supplier_id=data.get('supplier_id') or None,
                status=data.get('status','active'), image_url=data.get('image_url',''))
    db.session.add(p); db.session.commit()
    return jsonify({'status':'success','product':{'id':p.id,'name':p.name}}), 201

@shop_bp.route('/products/detail', methods=['GET'])
@token_required
@boutique_required
def shop_get_product():
    pid = request.args.get('id', type=int)
    if not pid: return jsonify({'status':'error','message':'id requis'}), 400
    p = db.session.get(Product, pid)
    if not p: return jsonify({'status':'error','message':'Produit introuvable'}), 404
    return jsonify({'status':'success','product':_product_json(p)})

@shop_bp.route('/products/update', methods=['POST'])
@token_required
@gestionnaire_required
def shop_update_product():
    data = request.get_json() or {}
    pid = data.get('id')
    if not pid: return jsonify({'status':'error','message':'id requis'}), 400
    p = db.session.get(Product, int(pid))
    if not p: return jsonify({'status':'error','message':'Produit introuvable'}), 404
    p.name = data.get('name', p.name); p.description = data.get('description', p.description)
    p.category = data.get('category', p.category); p.price = data.get('price', p.price)
    p.stock_quantity = data.get('stock_quantity', p.stock_quantity); p.supplier_id = data.get('supplier_id', p.supplier_id) or None
    p.status = data.get('status', p.status); p.image_url = data.get('image_url', p.image_url)
    db.session.commit()
    return jsonify({'status':'success','product':{'id':p.id,'name':p.name}})

@shop_bp.route('/products/delete', methods=['POST'])
@token_required
@gestionnaire_required
def shop_delete_product():
    data = request.get_json() or {}
    pid = data.get('id')
    if not pid: return jsonify({'status':'error','message':'id requis'}), 400
    p = db.session.get(Product, int(pid))
    if not p: return jsonify({'status':'error','message':'Produit introuvable'}), 404
    if OrderItem.query.filter_by(product_id=p.id).first():
        p.status = 'inactive'; db.session.commit()   # déjà vendu : on le retire du catalogue sans casser l'historique
        return jsonify({'status':'success','message':'Produit retiré du catalogue (déjà présent dans des commandes)'})
    CartItem.query.filter_by(product_id=p.id).delete()
    db.session.delete(p); db.session.commit()
    return jsonify({'status':'success','message':'Produit supprimé'})

# ── Panier ─────────────────────────────────────────────────
@shop_bp.route('/cart', methods=['GET'])
@token_required
@boutique_required
def shop_get_cart():
    user_id = request.current_user.id
    items = CartItem.query.filter_by(user_id=user_id).all()
    result = []; total = 0
    for it in items:
        p = db.session.get(Product, it.product_id)
        if p:
            sub = float(p.price or 0) * it.quantity; total += sub
            result.append({'id':it.id,'product_id':p.id,'name':p.name,'price':float(p.price or 0),'quantity':it.quantity,'subtotal':sub,'image_url':p.image_url})
    return jsonify({'status':'success','items':result,'total':total,'count':len(result),'wave_marchand':'Formation'})

@shop_bp.route('/cart/add', methods=['POST'])
@token_required
@boutique_required
def shop_add_cart():
    data = request.get_json() or {}
    user_id = request.current_user.id
    try:
        product_id = int(data.get('product_id') or 0); qty = int(data.get('quantity', 1) or 1)
    except (TypeError, ValueError):
        return jsonify({'status':'error','message':'Produit ou quantité invalide'}), 400
    if not product_id or qty < 1 or qty > 999: return jsonify({'status':'error','message':'Produit ou quantité invalide'}), 400
    p = db.session.get(Product, product_id)
    if not p or p.status != 'active': return jsonify({'status':'error','message':'Produit indisponible'}), 404
    existing = CartItem.query.filter_by(user_id=user_id, product_id=product_id).first()
    deja = existing.quantity if existing else 0
    if (p.stock_quantity or 0) < deja + qty:
        return jsonify({'status':'error','message':f'Stock insuffisant pour « {p.name} » ({p.stock_quantity or 0} disponible(s))'}), 409
    if existing: existing.quantity += qty
    else: db.session.add(CartItem(user_id=user_id, product_id=product_id, quantity=qty))
    db.session.commit()
    return jsonify({'status':'success','message':'Ajouté au panier'})

@shop_bp.route('/cart/remove', methods=['POST'])
@token_required
@boutique_required
def shop_remove_cart():
    data = request.get_json() or {}
    cid = data.get('id')
    if not cid: return jsonify({'status':'error','message':'id requis'}), 400
    item = db.session.get(CartItem, int(cid))
    if item and item.user_id == request.current_user.id:
        db.session.delete(item); db.session.commit()
    return jsonify({'status':'success','message':'Retiré du panier'})

@shop_bp.route('/cart/clear', methods=['POST'])
@token_required
@boutique_required
def shop_clear_cart():
    CartItem.query.filter_by(user_id=request.current_user.id).delete()
    db.session.commit()
    return jsonify({'status':'success','message':'Panier vidé'})

# ── Commandes ──────────────────────────────────────────────
@shop_bp.route('/orders', methods=['GET'])
@token_required
@boutique_required
def shop_list_orders():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', request.args.get('limit', 10, type=int), type=int)
    q = Order.query
    if not est_gestionnaire(request.current_user): q = q.filter(Order.user_id == request.current_user.id)
    statut = request.args.get('payment_status', '').strip()
    if statut: q = q.filter(Order.payment_status == statut)
    q = q.order_by(Order.created_at.desc())
    total = q.count()
    orders = q.offset((page-1)*per_page).limit(per_page).all()
    a_verifier = Order.query.filter_by(payment_status='declared').count() if est_gestionnaire(request.current_user) else None
    return jsonify({'status':'success','page':page,'per_page':per_page,'total':total,'a_verifier':a_verifier,'orders':[order_json(o) for o in orders]})

@shop_bp.route('/orders/create', methods=['POST'])
@token_required
@boutique_required
def shop_create_order():
    user = request.current_user
    data = request.get_json() or {}
    cart_items = CartItem.query.filter_by(user_id=user.id).all()
    if not cart_items: return jsonify({'status':'error','message':'Panier vide'}), 400
    lignes = []
    for ci in cart_items:
        p = db.session.get(Product, ci.product_id)
        if not p or p.status != 'active':
            return jsonify({'status':'error','message':'Un produit du panier n\'est plus disponible : retirez-le puis recommencez.'}), 409
        if (p.stock_quantity or 0) < ci.quantity:
            return jsonify({'status':'error','message':f'Stock insuffisant pour « {p.name} » ({p.stock_quantity or 0} disponible(s))'}), 409
        lignes.append((p, ci.quantity))
    total = sum(float(p.price or 0) * q for p, q in lignes)
    if total <= 0: return jsonify({'status':'error','message':'Montant de la commande invalide'}), 400
    order = Order(order_number=generate_order_number(), user_id=user.id, total_amount=total,
                  status='pending', payment_status='pending', payment_method='wave_formation',
                  region=data.get('region') or user.region or '', commune=data.get('commune') or user.commune or '')
    db.session.add(order); db.session.flush()
    fournisseurs = {}
    for p, q in lignes:
        sub = float(p.price or 0) * q
        db.session.add(OrderItem(order_id=order.id, product_id=p.id, quantity=q, unit_price=p.price, total_price=sub))
        if p.supplier_id: fournisseurs.setdefault(p.supplier_id, []).append(p.name)
    invoice = Invoice(order_id=order.id, invoice_number=generate_invoice_number(), amount=total, status='pending',
                      due_date=datetime.date.today() + datetime.timedelta(days=7))
    db.session.add(invoice)
    # Livraisons préparées, mais lancées seulement après validation du paiement
    if fournisseurs:
        for sid, noms in fournisseurs.items():
            s = db.session.get(Supplier, sid)
            if not s: continue
            db.session.add(Delivery(order_id=order.id, supplier_id=s.id, status='awaiting_payment',
                                    address=s.address or data.get('address',''), region=s.region or order.region, commune=s.commune or order.commune,
                                    delivery_person=s.contact_name or 'Livreur assigné', delivery_phone=s.phone or '',
                                    notes=f"{len(noms)} article(s) : {', '.join(noms[:3])}{'…' if len(noms) > 3 else ''} — départ après validation du paiement"))
    else:
        db.session.add(Delivery(order_id=order.id, status='awaiting_payment', region=order.region, commune=order.commune,
                                delivery_person="Livreur en attente d'assignation", notes='Départ après validation du paiement'))
    CartItem.query.filter_by(user_id=user.id).delete()
    db.session.commit()
    return jsonify({'status':'success',
                    'order':{'id':order.id,'order_number':order.order_number,'total_amount':float(total),'payment_status':order.payment_status},
                    'invoice':{'invoice_number':invoice.invoice_number,'amount':float(total),'status':invoice.status,'due_date':str(invoice.due_date)},
                    'wave_url': lien_wave(total), 'wave_marchand':'Formation',
                    'instructions':'Payez avec Wave, puis saisissez la référence de la transaction Wave : votre commande sera confirmée après vérification par VoteConnect.'}), 201

@shop_bp.route('/orders/detail', methods=['GET'])
@token_required
@boutique_required
def shop_get_order():
    oid = request.args.get('id', type=int)
    if not oid: return jsonify({'status':'error','message':'id requis'}), 400
    o = db.session.get(Order, oid)
    if not _commande_visible(o): return jsonify({'status':'error','message':'Commande introuvable'}), 404
    return jsonify({'status':'success','order':order_json(o, details=True)})

@shop_bp.route('/orders/declare-payment', methods=['POST'])
@token_required
@boutique_required
def shop_declare_payment():
    data = request.get_json() or {}
    o = db.session.get(Order, int(data.get('id') or 0)) if str(data.get('id') or '').isdigit() else None
    if not o or o.user_id != request.current_user.id:
        return jsonify({'status':'error','message':'Commande introuvable'}), 404
    if o.payment_status not in ('pending', 'rejected'):
        msg = {'declared':'Paiement déjà déclaré : vérification en cours.','paid':'Commande déjà payée.','cancelled':'Commande annulée.'}.get(o.payment_status, 'Paiement non modifiable.')
        return jsonify({'status':'error','message':msg}), 409
    ref = norm_ref_wave(data.get('reference'))
    if not re.fullmatch(r'[A-Z0-9]{6,30}', ref):
        return jsonify({'status':'error','message':'Référence Wave invalide : 6 à 30 lettres ou chiffres, telle qu\'elle figure sur votre reçu Wave.'}), 400
    deja = Order.query.filter(Order.wave_reference == ref, Order.id != o.id, Order.payment_status.in_(('declared', 'paid'))).first()
    if deja: return jsonify({'status':'error','message':'Cette référence Wave a déjà été utilisée pour une autre commande.'}), 409
    o.wave_reference = ref; o.payment_status = 'declared'; o.payment_method = 'wave_formation'
    o.payment_declared_at = datetime.datetime.utcnow(); o.payment_note = None
    db.session.commit()
    return jsonify({'status':'success','message':'Référence reçue : paiement en cours de vérification par VoteConnect.','order':order_json(o)})

@shop_bp.route('/orders/validate-payment', methods=['POST'])
@token_required
@gestionnaire_required
def shop_validate_payment():
    data = request.get_json() or {}
    o = db.session.get(Order, int(data.get('id') or 0)) if str(data.get('id') or '').isdigit() else None
    if not o: return jsonify({'status':'error','message':'Commande introuvable'}), 404
    if o.payment_status != 'declared':
        return jsonify({'status':'error','message':'Seul un paiement déclaré (référence saisie) peut être validé ou rejeté.'}), 409
    decision = str(data.get('decision') or '').lower()
    maintenant = datetime.datetime.utcnow()
    if decision == 'rejeter':
        motif = str(data.get('motif') or '').strip()[:200] or 'Paiement introuvable dans Wave'
        o.payment_note = f"Référence {o.wave_reference} rejetée : {motif}"
        o.payment_status = 'rejected'; o.wave_reference = None
        o.payment_validated_at = maintenant; o.payment_validated_by = request.current_user.id
        db.session.commit()
        return jsonify({'status':'success','message':'Paiement rejeté : le client peut saisir une nouvelle référence.','order':order_json(o)})
    if decision != 'valider': return jsonify({'status':'error','message':'decision = valider ou rejeter'}), 400
    items = OrderItem.query.filter_by(order_id=o.id).all()
    for it in items:   # le stock a pu bouger depuis la commande
        p = db.session.get(Product, it.product_id)
        if p and (p.stock_quantity or 0) < it.quantity:
            return jsonify({'status':'error','message':f'Stock insuffisant pour « {p.name} » : réapprovisionnez avant de valider.'}), 409
    for it in items:
        p = db.session.get(Product, it.product_id)
        if p:
            p.stock_quantity = (p.stock_quantity or 0) - it.quantity
            db.session.add(StockMovement(product_id=p.id, movement_type='out', quantity=it.quantity, reason=f'Commande {o.order_number} (payée)'))
    o.payment_status = 'paid'; o.status = 'confirmed'
    o.payment_validated_at = maintenant; o.payment_validated_by = request.current_user.id
    inv = Invoice.query.filter_by(order_id=o.id).first()
    if inv: inv.status = 'paid'; inv.paid_at = maintenant
    for dl in Delivery.query.filter_by(order_id=o.id).all():
        if dl.status == 'awaiting_payment': dl.status = 'pending'
    db.session.commit()
    return jsonify({'status':'success','message':'Paiement validé : commande confirmée, facture payée, livraison lancée.','order':order_json(o)})

@shop_bp.route('/orders/cancel', methods=['POST'])
@token_required
@boutique_required
def shop_cancel_order():
    data = request.get_json() or {}
    o = db.session.get(Order, int(data.get('id') or 0)) if str(data.get('id') or '').isdigit() else None
    if not _commande_visible(o): return jsonify({'status':'error','message':'Commande introuvable'}), 404
    if o.payment_status not in ('pending', 'rejected'):
        return jsonify({'status':'error','message':'Seule une commande non payée et sans paiement en cours de vérification peut être annulée.'}), 409
    o.status = 'cancelled'; o.payment_status = 'cancelled'
    inv = Invoice.query.filter_by(order_id=o.id).first()
    if inv: inv.status = 'cancelled'
    for dl in Delivery.query.filter_by(order_id=o.id).all(): dl.status = 'cancelled'
    db.session.commit()
    return jsonify({'status':'success','message':'Commande annulée','order':order_json(o)})

@shop_bp.route('/orders/update', methods=['POST'])
@token_required
@gestionnaire_required
def shop_update_order():
    data = request.get_json() or {}
    o = db.session.get(Order, int(data.get('id') or 0)) if str(data.get('id') or '').isdigit() else None
    if not o: return jsonify({'status':'error','message':'Commande introuvable'}), 404
    statut = data.get('status')
    if statut:
        if o.payment_status != 'paid' or statut not in STATUTS_COMMANDE_APRES_PAIEMENT:
            return jsonify({'status':'error','message':'Le suivi (traitement, expédition, livraison) ne s\'applique qu\'à une commande payée. Le paiement se valide uniquement par « Valider le paiement ».'}), 409
        o.status = statut
    db.session.commit()
    return jsonify({'status':'success','order':{'id':o.id,'status':o.status}})

@shop_bp.route('/orders/delete', methods=['POST'])
@token_required
@gestionnaire_required
def shop_delete_order():
    data = request.get_json() or {}
    o = db.session.get(Order, int(data.get('id') or 0)) if str(data.get('id') or '').isdigit() else None
    if not o: return jsonify({'status':'error','message':'Commande introuvable'}), 404
    if o.payment_status in ('paid', 'declared'):
        return jsonify({'status':'error','message':'Une commande payée ou en cours de vérification ne se supprime pas (trace comptable).'}), 409
    OrderItem.query.filter_by(order_id=o.id).delete()
    Delivery.query.filter_by(order_id=o.id).delete()
    Invoice.query.filter_by(order_id=o.id).delete()
    db.session.delete(o); db.session.commit()
    return jsonify({'status':'success','message':'Commande supprimée'})

# ── Fournisseurs (Gestionnaire) ────────────────────────────
def _supplier_json(s):
    return {'id':s.id,'name':s.name,'contact_name':s.contact_name,'phone':s.phone,'email':s.email,'region':s.region,'commune':s.commune,'address':s.address,'status':s.status,'created_at':s.created_at.isoformat() if s.created_at else None}

@shop_bp.route('/suppliers', methods=['GET'])
@token_required
@gestionnaire_required
def shop_list_suppliers():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', request.args.get('limit', 10, type=int), type=int)
    q = Supplier.query.order_by(Supplier.created_at.desc())
    total = q.count()
    return jsonify({'status':'success','page':page,'per_page':per_page,'total':total,'suppliers':[_supplier_json(s) for s in q.offset((page-1)*per_page).limit(per_page).all()]})

@shop_bp.route('/suppliers', methods=['POST'])
@token_required
@gestionnaire_required
def shop_create_supplier():
    data = request.get_json() or {}
    if not str(data.get('name') or '').strip(): return jsonify({'status':'error','message':'Nom du fournisseur requis'}), 400
    s = Supplier(name=data.get('name',''), contact_name=data.get('contact_name',''), phone=data.get('phone',''),
                 email=data.get('email',''), region=data.get('region',''), commune=data.get('commune',''),
                 address=data.get('address',''), status=data.get('status','active'))
    db.session.add(s); db.session.commit()
    return jsonify({'status':'success','supplier':{'id':s.id,'name':s.name}}), 201

@shop_bp.route('/suppliers/detail', methods=['GET'])
@token_required
@gestionnaire_required
def shop_get_supplier():
    sid = request.args.get('id', type=int)
    s = db.session.get(Supplier, sid) if sid else None
    if not s: return jsonify({'status':'error','message':'Fournisseur introuvable'}), 404
    return jsonify({'status':'success','supplier':_supplier_json(s)})

@shop_bp.route('/suppliers/update', methods=['POST'])
@token_required
@gestionnaire_required
def shop_update_supplier():
    data = request.get_json() or {}
    s = db.session.get(Supplier, int(data.get('id') or 0)) if str(data.get('id') or '').isdigit() else None
    if not s: return jsonify({'status':'error','message':'Fournisseur introuvable'}), 404
    for k in ('name','contact_name','phone','email','region','commune','address','status'):
        if k in data: setattr(s, k, data.get(k))
    db.session.commit()
    return jsonify({'status':'success','supplier':{'id':s.id,'name':s.name}})

@shop_bp.route('/suppliers/delete', methods=['POST'])
@token_required
@gestionnaire_required
def shop_delete_supplier():
    data = request.get_json() or {}
    s = db.session.get(Supplier, int(data.get('id') or 0)) if str(data.get('id') or '').isdigit() else None
    if not s: return jsonify({'status':'error','message':'Fournisseur introuvable'}), 404
    if Product.query.filter_by(supplier_id=s.id).first() or Delivery.query.filter_by(supplier_id=s.id).first():
        s.status = 'inactive'; db.session.commit()
        return jsonify({'status':'success','message':'Fournisseur désactivé (lié à des produits ou livraisons)'})
    db.session.delete(s); db.session.commit()
    return jsonify({'status':'success','message':'Fournisseur supprimé'})

# ── Livraisons ─────────────────────────────────────────────
def _delivery_json(d):
    o = db.session.get(Order, d.order_id)
    s = db.session.get(Supplier, d.supplier_id) if d.supplier_id else None
    return {'id':d.id,'order_id':d.order_id,'order_number':o.order_number if o else '—','status':d.status,'tracking_number':d.tracking_number,'address':d.address,'region':d.region,'commune':d.commune,'estimated_date':str(d.estimated_date) if d.estimated_date else None,'delivered_at':d.delivered_at.isoformat() if d.delivered_at else None,'delivery_person':d.delivery_person,'delivery_phone':d.delivery_phone,'supplier_name':s.name if s else '—','notes':d.notes,'created_at':d.created_at.isoformat() if d.created_at else None}

@shop_bp.route('/deliveries', methods=['GET'])
@token_required
@boutique_required
def shop_list_deliveries():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', request.args.get('limit', 10, type=int), type=int)
    q = Delivery.query
    ids = _ids_commandes_visibles()
    if ids is not None: q = q.filter(Delivery.order_id.in_(ids or [0]))
    q = q.order_by(Delivery.created_at.desc())
    total = q.count()
    return jsonify({'status':'success','page':page,'per_page':per_page,'total':total,'deliveries':[_delivery_json(d) for d in q.offset((page-1)*per_page).limit(per_page).all()]})

@shop_bp.route('/deliveries', methods=['POST'])
@token_required
@gestionnaire_required
def shop_create_delivery():
    data = request.get_json() or {}
    o = db.session.get(Order, int(data.get('order_id') or 0)) if str(data.get('order_id') or '').isdigit() else None
    if not o: return jsonify({'status':'error','message':'Commande introuvable'}), 404
    d = Delivery(order_id=o.id, status='pending' if o.payment_status == 'paid' else 'awaiting_payment', tracking_number=data.get('tracking_number',''),
                 address=data.get('address',''), region=data.get('region',''), commune=data.get('commune',''),
                 estimated_date=datetime.datetime.strptime(data['estimated_date'],'%Y-%m-%d').date() if data.get('estimated_date') else None,
                 notes=data.get('notes',''))
    db.session.add(d); db.session.commit()
    return jsonify({'status':'success','delivery':{'id':d.id,'order_id':d.order_id}}), 201

@shop_bp.route('/deliveries/detail', methods=['GET'])
@token_required
@boutique_required
def shop_get_delivery():
    did = request.args.get('id', type=int)
    d = db.session.get(Delivery, did) if did else None
    if not d or not _commande_visible(db.session.get(Order, d.order_id)): return jsonify({'status':'error','message':'Livraison introuvable'}), 404
    return jsonify({'status':'success','delivery':_delivery_json(d)})

@shop_bp.route('/deliveries/update', methods=['POST'])
@token_required
@gestionnaire_required
def shop_update_delivery():
    data = request.get_json() or {}
    d = db.session.get(Delivery, int(data.get('id') or 0)) if str(data.get('id') or '').isdigit() else None
    if not d: return jsonify({'status':'error','message':'Livraison introuvable'}), 404
    o = db.session.get(Order, d.order_id)
    nouveau = data.get('status')
    if nouveau and nouveau != d.status:
        if not o or o.payment_status != 'paid':
            return jsonify({'status':'error','message':'La livraison ne peut démarrer qu\'après la validation du paiement.'}), 409
        if nouveau not in STATUTS_LIVRAISON_OK: return jsonify({'status':'error','message':'Statut de livraison invalide'}), 400
        d.status = nouveau
        if nouveau == 'delivered' and not d.delivered_at: d.delivered_at = datetime.datetime.utcnow()
    for k in ('tracking_number','address','region','commune','notes','delivery_person','delivery_phone'):
        if k in data: setattr(d, k, data.get(k))
    if data.get('supplier_id'): d.supplier_id = data.get('supplier_id')
    if data.get('estimated_date'): d.estimated_date = datetime.datetime.strptime(data['estimated_date'],'%Y-%m-%d').date()
    if data.get('delivered_at'): d.delivered_at = datetime.datetime.strptime(data['delivered_at'],'%Y-%m-%dT%H:%M:%S')
    db.session.commit()
    return jsonify({'status':'success','delivery':{'id':d.id,'status':d.status}})

# ── Factures ───────────────────────────────────────────────
def _invoice_json(inv):
    o = db.session.get(Order, inv.order_id)
    return {'id':inv.id,'order_id':inv.order_id,'order_number':o.order_number if o else '—','invoice_number':inv.invoice_number,'amount':float(inv.amount or 0),'status':inv.status,'issued_at':inv.issued_at.isoformat() if inv.issued_at else None,'paid_at':inv.paid_at.isoformat() if inv.paid_at else None,'due_date':str(inv.due_date) if inv.due_date else None}

@shop_bp.route('/invoices', methods=['GET'])
@token_required
@boutique_required
def shop_list_invoices():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', request.args.get('limit', 10, type=int), type=int)
    q = Invoice.query
    ids = _ids_commandes_visibles()
    if ids is not None: q = q.filter(Invoice.order_id.in_(ids or [0]))
    q = q.order_by(Invoice.issued_at.desc())
    total = q.count()
    return jsonify({'status':'success','page':page,'per_page':per_page,'total':total,'invoices':[_invoice_json(i) for i in q.offset((page-1)*per_page).limit(per_page).all()]})

@shop_bp.route('/invoices', methods=['POST'])
@token_required
@gestionnaire_required
def shop_create_invoice():
    return jsonify({'status':'error','message':'Les factures sont créées automatiquement avec chaque commande.'}), 410

@shop_bp.route('/invoices/detail', methods=['GET'])
@token_required
@boutique_required
def shop_get_invoice():
    iid = request.args.get('id', type=int)
    inv = db.session.get(Invoice, iid) if iid else None
    if not inv or not _commande_visible(db.session.get(Order, inv.order_id)): return jsonify({'status':'error','message':'Facture introuvable'}), 404
    return jsonify({'status':'success','invoice':_invoice_json(inv)})

@shop_bp.route('/invoices/update', methods=['POST'])
@token_required
@gestionnaire_required
def shop_update_invoice():
    data = request.get_json() or {}
    inv = db.session.get(Invoice, int(data.get('id') or 0)) if str(data.get('id') or '').isdigit() else None
    if not inv: return jsonify({'status':'error','message':'Facture introuvable'}), 404
    if 'status' in data and data.get('status') != inv.status:
        return jsonify({'status':'error','message':'Une facture devient « payée » uniquement par la validation du paiement Wave de sa commande.'}), 409
    if data.get('due_date'): inv.due_date = datetime.datetime.strptime(data['due_date'],'%Y-%m-%d').date()
    db.session.commit()
    return jsonify({'status':'success','invoice':{'id':inv.id,'status':inv.status}})

# ── Stocks (Gestionnaire) ──────────────────────────────────
@shop_bp.route('/stock-movements', methods=['GET'])
@token_required
@gestionnaire_required
def shop_list_stock():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', request.args.get('limit', 10, type=int), type=int)
    product_id = request.args.get('product_id', type=int)
    q = StockMovement.query.order_by(StockMovement.created_at.desc())
    if product_id: q = q.filter_by(product_id=product_id)
    total = q.count()
    result = []
    for m in q.offset((page-1)*per_page).limit(per_page).all():
        p = db.session.get(Product, m.product_id)
        result.append({'id':m.id,'product_id':m.product_id,'product_name':p.name if p else '—','movement_type':m.movement_type,'quantity':m.quantity,'reason':m.reason,'created_at':m.created_at.isoformat() if m.created_at else None})
    return jsonify({'status':'success','page':page,'per_page':per_page,'total':total,'movements':result})

@shop_bp.route('/stock-movements/add', methods=['POST'])
@token_required
@gestionnaire_required
def shop_add_stock():
    data = request.get_json() or {}
    try:
        pid = int(data.get('product_id') or 0); qty = int(data.get('quantity', 0) or 0)
    except (TypeError, ValueError):
        return jsonify({'status':'error','message':'Produit ou quantité invalide'}), 400
    mtype = 'out' if data.get('movement_type') == 'out' else 'in'
    p = db.session.get(Product, pid) if pid else None
    if not p: return jsonify({'status':'error','message':'Produit introuvable'}), 404
    if qty <= 0: return jsonify({'status':'error','message':'Quantité invalide'}), 400
    if mtype == 'in': p.stock_quantity = (p.stock_quantity or 0) + qty
    else: p.stock_quantity = max(0, (p.stock_quantity or 0) - qty)
    db.session.add(StockMovement(product_id=pid, movement_type=mtype, quantity=qty, reason=data.get('reason','Ajustement manuel')))
    db.session.commit()
    return jsonify({'status':'success','message':'Stock mis à jour','product':{'id':p.id,'stock_quantity':p.stock_quantity}})

@shop_bp.route('/stock-movements/product', methods=['GET'])
@token_required
@gestionnaire_required
def shop_stock_by_product():
    pid = request.args.get('id', type=int)
    p = db.session.get(Product, pid) if pid else None
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
        declared_orders = Order.query.filter_by(payment_status='declared').count()
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
        return jsonify({'token': make_bot_link_token(phone)})
    except Exception as e:
        db.session.rollback()
        import traceback
        traceback.print_exc()
        return jsonify({'status':'error','message':str(e)}), 500

# ============================================================
# BLUEPRINTS INIT / SEED
# ============================================================
init_bp = Blueprint('init', __name__, url_prefix='/api')

@init_bp.route('/init-db', methods=['GET','POST'])
@reset_key_required
def init_db():
    try:
        db.drop_all(); db.create_all()
        return jsonify({'status':'success','message':'Base de donnees reinitialisee (soft reset)'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'status':'error','message':str(e)}), 500

seed_bp = Blueprint('seed', __name__, url_prefix='/api')

@seed_bp.route('/seed', methods=['GET','POST'])
@reset_key_required
def seed():
    try:
        db.session.query(StockMovement).delete(); db.session.query(Invoice).delete()
        db.session.query(Delivery).delete(); db.session.query(OrderItem).delete()
        db.session.query(CartItem).delete(); db.session.query(Product).delete()
        db.session.query(Supplier).delete()
        db.session.query(Order).delete(); db.session.query(Campaign).delete()
        for u in User.query.all():   # v2.11.0 : les comptes officiels VoteConnect sont conservés
            if not est_officiel(u): db.session.delete(u)
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
                     role='user', status='inactive', region=region, commune=commune, profile_type=ptype, ngd_id=generate_ngd_id())
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
            ('Affiche A3 (lot 100)', 'Affiches électorales haute qualité format A3', 'imprimerie', 100000, 20, s2.id, 'https://i.ibb.co/LdqjWMGL/Affiche-A3-Saa-S.png'),
            ('Brainstorming Session', 'Session de brainstorming stratégique 2h', 'service', 500000, 999, s1.id, 'https://i.ibb.co/xS5k3rxH/Brainstorming-Saa-S.png'),
            ('Casquette Coalition 509', 'Casquette brodée logo officiel', 'textile', 5000, 30, s1.id, 'https://i.ibb.co/DP6hYrPx/Casquettes-Saa-S.png'),
            ('Flyers A5 (lot 500)', 'Flyers recto/verso couleur', 'imprimerie', 35000, 100, s2.id, 'https://i.ibb.co/1fgqRWQm/Flyers-Saa-S.png'),
            ('Pack Hôtel Électoral', 'Réservation hôtel + transport pour équipe', 'service', 75000, 50, s1.id, 'https://i.ibb.co/8DcPN4w9/H-tel-Saa-S.png'),
            ('Pack Locomotion', 'Location véhicule + carburant journée', 'service', 45000, 30, s1.id, 'https://i.ibb.co/jPPNBQ3T/Locomotion-Saa-S.png'),
            ('Personal Branding', 'Kit photo + CV politique + réseaux', 'service', 350000, 100, s2.id, 'https://i.ibb.co/ynLW4hpC/Personnal-Branding-Saa-S.png'),
            ('Podcast Campagne', 'Production podcast 3 épisodes', 'service', 200000, 20, s2.id, 'https://i.ibb.co/vbdGJqr/Podcast-Saa-S.png'),
            ('Pack Restaurant', 'Traiteur 50 personnes + mobilier', 'service', 135000, 10, s1.id, 'https://i.ibb.co/ZzHFc5H9/Restaurant-Saa-S.png'),
            ('T-Shirt Coalition 509', 'T-shirt officiel 100% coton', 'textile', 5000, 50, s1.id, 'https://i.ibb.co/QFsDrWqZ/T-Shirts-Saa-S.png'),
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
        declared_orders = Order.query.filter_by(payment_status='declared').count()
        total_revenue = db.session.query(db.func.sum(Order.total_amount)).filter_by(payment_status='paid').scalar() or 0
        total_products = Product.query.count(); low_stock = Product.query.filter(Product.stock_quantity <= 5).count()
        total_suppliers = Supplier.query.count(); total_invoices = Invoice.query.count()
        return jsonify({'total_users':total_users,'total_campaigns':total_campaigns,'total_orders':total_orders,'pending_orders':pending_orders,'paid_orders':paid_orders,'declared_orders':declared_orders,'total_revenue':float(total_revenue),'total_groups':0,'pending_withdrawals':0,'total_products':total_products,'low_stock':low_stock,'total_suppliers':total_suppliers,'total_invoices':total_invoices})
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
@annuaire_required
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
    # v2.10.0 — répondait « confirmé » à toute demande, sans rien vérifier : fermée.
    return jsonify(PAIEMENT_FERME), 410

@v1_bp.route('/export/users', methods=['GET'])
@token_required
@gestionnaire_required
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
    q = Order.query if est_gestionnaire(request.current_user) else Order.query.filter_by(user_id=request.current_user.id)   # v2.11.0
    for o in q.all(): writer.writerow([o.id,o.order_number,o.total_amount,o.status,o.payment_status,o.region,o.commune])
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

# ============================================================
# GUICHET STATISTIQUES — HUB PARTENAIRES (v2.9.8)
# GET /api/stats-partenaires?du=AAAA-MM-JJ&au=AAAA-MM-JJ  —  en-tête X-Stats-Key
# Lecture seule, aucune donnée personnelle.
# ============================================================
STATS_KEY = os.environ.get('STATS_KEY', '')
COMMISSION_PCT = float(os.environ.get('COMMISSION_PCT', '10') or 0)
VC_PRODUITS_PROPRES = [x.strip().lower() for x in os.environ.get(
    'VC_PRODUITS_PROPRES', 'Podcast Campagne,Personal Branding,Brainstorming Session').split(',') if x.strip()]

def part_voteconnect(nom_produit):
    """Part du prix qui revient à VoteConnect SARL (1.0 = prestation vendue en propre)."""
    if (nom_produit or '').strip().lower() in VC_PRODUITS_PROPRES: return 1.0
    return COMMISSION_PCT / 100.0

def _stats_cle_valide(fournie):
    attendue = STATS_KEY or ''
    return len(attendue) >= 16 and hmac.compare_digest(fournie or '', attendue)

def _periode(du, au):
    try:
        d = datetime.datetime.strptime(du, '%Y-%m-%d').date(); a = datetime.datetime.strptime(au, '%Y-%m-%d').date()
    except (TypeError, ValueError):
        return None
    if d > a: d, a = a, d
    if (a - d).days > 366: return None
    return d, a

@app.route('/api/stats-partenaires', methods=['GET'])
def stats_partenaires():
    if not STATS_KEY: return jsonify({'ok': False, 'error': 'Guichet désactivé (STATS_KEY absent).'}), 503
    if not _stats_cle_valide(request.headers.get('X-Stats-Key', '')): return jsonify({'ok': False, 'error': 'non autorisé'}), 401
    per = _periode(request.args.get('du', ''), request.args.get('au', ''))
    if not per: return jsonify({'ok': False, 'error': 'Période invalide (AAAA-MM-JJ, 366 jours maximum).'}), 400
    du, au = per
    try:
        debut = datetime.datetime.combine(du, datetime.time.min); fin = datetime.datetime.combine(au + datetime.timedelta(days=1), datetime.time.min)
        acc = {}
        def cumuler(date, flux, region, brut, net, nb=1):
            k = (date, flux, region)
            l = acc.setdefault(k, {'date': date, 'flux': flux, 'type': 'REVENU', 'region': region, 'brut': 0.0, 'net': 0.0, 'nb': 0})
            l['brut'] += brut; l['net'] += net; l['nb'] += nb
        commandes = Order.query.filter(Order.payment_status == 'paid').all()
        for o in commandes:
            inv = Invoice.query.filter_by(order_id=o.id).first()
            quand = (inv.paid_at if inv and inv.paid_at else None) or o.created_at
            if not quand or quand < debut or quand >= fin: continue
            jour = quand.strftime('%Y-%m-%d'); region = o.region or ''
            items = OrderItem.query.filter_by(order_id=o.id).all()
            if not items:
                cumuler(jour, 'Place de marché — fournisseurs', region, float(o.total_amount or 0), float(o.total_amount or 0) * COMMISSION_PCT / 100.0)
                continue
            for it in items:
                p = db.session.get(Product, it.product_id)
                brut = float(it.total_price or 0) or float(it.unit_price or 0) * (it.quantity or 1)
                part = part_voteconnect(p.name if p else '')
                flux = 'Place de marché — prestations VoteConnect' if part >= 1 else f'Place de marché — fournisseurs ({COMMISSION_PCT:g} %)'
                cumuler(jour, flux, region, brut, brut * part)
        lignes = sorted(acc.values(), key=lambda l: (l['date'], l['flux']))
        for l in lignes: l['brut'] = round(l['brut']); l['net'] = round(l['net'])
        indicateurs = {
            'Produits au catalogue': Product.query.filter_by(status='active').count(),
            'Commandes en attente de paiement': Order.query.filter_by(payment_status='pending').count(),
            'Paiements Wave à vérifier': Order.query.filter_by(payment_status='declared').count(),
            'Commission fournisseurs': f'{COMMISSION_PCT:g} %',
        }
        return jsonify({'ok': True, 'service': 'coalition509-api', 'version': '2.11.0', 'periode': {'du': str(du), 'au': str(au)}, 'lignes': lignes, 'indicateurs': indicateurs})
    except Exception as e:
        db.session.rollback()
        print(f"[STATS-PARTENAIRES] {e}")
        return jsonify({'ok': False, 'error': 'erreur interne'}), 500

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
    return jsonify({'service':'Coalition 509 API','version':'2.11.0','status':'ok','modules':['auth','campaigns','users','orders','bot','shop'],'boutique':{'paiement':'Wave — marchand Formation','gestionnaires_configures':len(GESTIONNAIRES_BOUTIQUE)}})

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

            # Nouvelles colonnes Campaign v2.9.6
            result5 = conn.execute(db.text("SELECT column_name FROM information_schema.columns WHERE table_name='campaigns' AND column_name='election_type'"))
            if not result5.fetchone():
                conn.execute(db.text("ALTER TABLE campaigns ADD COLUMN election_type VARCHAR(50)"))
                conn.commit()
                print("[MIGRATE] Colonne 'election_type' ajoutee a campaigns")
            else:
                print("[MIGRATE] Colonne 'election_type' deja presente")

            result6 = conn.execute(db.text("SELECT column_name FROM information_schema.columns WHERE table_name='campaigns' AND column_name='price'"))
            if not result6.fetchone():
                conn.execute(db.text("ALTER TABLE campaigns ADD COLUMN price NUMERIC(12,2) DEFAULT 0"))
                conn.commit()
                print("[MIGRATE] Colonne 'price' ajoutee a campaigns")
            else:
                print("[MIGRATE] Colonne 'price' deja presente")

            result7 = conn.execute(db.text("SELECT column_name FROM information_schema.columns WHERE table_name='campaigns' AND column_name='pricing_model'"))
            if not result7.fetchone():
                conn.execute(db.text("ALTER TABLE campaigns ADD COLUMN pricing_model VARCHAR(20) DEFAULT 'forfait'"))
                conn.commit()
                print("[MIGRATE] Colonne 'pricing_model' ajoutee a campaigns")
            else:
                print("[MIGRATE] Colonne 'pricing_model' deja presente")
        # v2.10.0 — paiement Wave vérifié
        with db.engine.connect() as conn:
            for col, typ in (('wave_reference', 'VARCHAR(40)'), ('payment_declared_at', 'TIMESTAMP'), ('payment_validated_at', 'TIMESTAMP'),
                             ('payment_validated_by', 'INTEGER'), ('payment_note', 'TEXT')):
                res = conn.execute(db.text(f"SELECT column_name FROM information_schema.columns WHERE table_name='orders' AND column_name='{col}'"))
                if not res.fetchone():
                    conn.execute(db.text(f"ALTER TABLE orders ADD COLUMN {col} {typ}"))
                    conn.commit()
                    print(f"[MIGRATE] Colonne '{col}' ajoutee a orders")
        # v2.11.0 — Candidats Têtes de liste
        with db.engine.connect() as conn:
            for col, typ in (('candidature', 'VARCHAR(150)'), ('promoted_at', 'TIMESTAMP'), ('promoted_by', 'INTEGER')):
                res = conn.execute(db.text(f"SELECT column_name FROM information_schema.columns WHERE table_name='users' AND column_name='{col}'"))
                if not res.fetchone():
                    conn.execute(db.text(f"ALTER TABLE users ADD COLUMN {col} {typ}"))
                    conn.commit()
                    print(f"[MIGRATE] Colonne '{col}' ajoutee a users")
    except Exception as e:
        print(f"[MIGRATE] {e}")

with app.app_context():
    db.create_all()
    print("[BOOT] Tables verifiees/creees v2.11.0")
    auto_migrate()
    try:
        preparer_comptes()
    except Exception as e:
        db.session.rollback(); print(f"[COMPTES] {e}")

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
