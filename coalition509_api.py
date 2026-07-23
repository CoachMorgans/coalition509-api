# ============================================================
# COALITION 509 SaaS — API Backend v1.0
# FastAPI + PostgreSQL (Supabase)
# VoteConnect Ecosystem | ChallengeFinancier™
# ============================================================

from fastapi import FastAPI, Depends, HTTPException, status, Query, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr, Field
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta
from contextlib import asynccontextmanager
import asyncpg
import jwt
import bcrypt
import os
import json

# ============================================================
# CONFIGURATION
# ============================================================
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://postgres:password@db.supabase.co:5432/postgres")
JWT_SECRET = os.getenv("JWT_SECRET", "coalition509-secret-key-change-in-production")
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = 24

# ============================================================
# LIFESPAN (connexion DB)
# ============================================================
@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.db = await asyncpg.create_pool(DATABASE_URL, min_size=2, max_size=10)
    print("✅ Connexion PostgreSQL établie")
    yield
    await app.state.db.close()
    print("🔒 Connexion PostgreSQL fermée")

app = FastAPI(
    title="Coalition 509 API",
    description="API Backend pour le SaaS Coalition 509 — Gestion de campagnes électorales",
    version="1.0.0",
    lifespan=lifespan
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # En prod: ["https://coalition509.vercel.app"]
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

security = HTTPBearer()

# ============================================================
# MODÈLES PYDANTIC
# ============================================================

class UserRegister(BaseModel):
    phone: str = Field(..., min_length=10, max_length=20)
    first_name: str = Field(..., min_length=1, max_length=100)
    last_name: str = Field(..., min_length=1, max_length=100)
    email: Optional[EmailStr] = None
    pin: str = Field(..., min_length=4, max_length=4, pattern=r"^\d{4}$")
    profile_type: Optional[str] = "Animateur NGD"
    region: Optional[str] = None
    commune: Optional[str] = None
    specialty: Optional[str] = None

class UserLogin(BaseModel):
    phone: str
    pin: str

class UserResponse(BaseModel):
    id: str
    phone: str
    first_name: str
    last_name: str
    email: Optional[str]
    role: str
    profile_type: Optional[str]
    region: Optional[str]
    commune: Optional[str]
    ngd_id: Optional[str]
    wallet_balance: int
    cashback_balance: int
    status: str
    created_at: datetime

class CampaignCreate(BaseModel):
    name: str = Field(..., min_length=3, max_length=255)
    election_type: str = Field(..., pattern=r"^(MUNICIPAL|REGIONAL|NATIONAL)$")
    region: str
    commune: Optional[str] = None
    election_date: Optional[str] = None
    description: Optional[str] = None

class CampaignResponse(BaseModel):
    id: str
    name: str
    slug: str
    election_type: str
    region: str
    commune: Optional[str]
    election_date: Optional[str]
    status: str
    owner_id: str
    created_at: datetime

class TeamMemberInvite(BaseModel):
    user_id: Optional[str] = None
    email: Optional[str] = None
    phone: Optional[str] = None
    role: str = Field(..., pattern=r"^(manager|agent_croire|agent_tcl|formateur|viewer)$")

class TeamMemberResponse(BaseModel):
    id: str
    campaign_id: str
    user_id: str
    role: str
    permissions: Dict[str, Any]
    status: str
    invited_at: datetime
    user: Optional[Dict[str, Any]] = None

class OrderCreate(BaseModel):
    items: List[Dict[str, Any]]
    delivery_mode: str
    address: Optional[str] = None
    region: Optional[str] = None
    commune: Optional[str] = None

class OrderResponse(BaseModel):
    id: str
    order_number: str
    total_amount: int
    status: str
    payment_status: str
    created_at: datetime

class WithdrawalRequest(BaseModel):
    amount: int = Field(..., gt=0)
    description: Optional[str] = None

class WithdrawalResponse(BaseModel):
    id: str
    transaction_number: str
    amount: int
    withdrawal_status: str
    created_at: datetime

class ConfigUpdate(BaseModel):
    config_value: str
    config_type: Optional[str] = "string"

class ActivityLogFilter(BaseModel):
    action_type: Optional[str] = None
    action_category: Optional[str] = None
    user_id: Optional[str] = None
    date_from: Optional[str] = None
    date_to: Optional[str] = None
    limit: int = 50
    offset: int = 0

# ============================================================
# HELPERS
# ============================================================

def hash_pin(pin: str) -> str:
    return bcrypt.hashpw(pin.encode(), bcrypt.gensalt()).decode()

def verify_pin(pin: str, hashed: str) -> bool:
    return bcrypt.checkpw(pin.encode(), hashed.encode())

def create_jwt(user_id: str, role: str, campaign_id: Optional[str] = None) -> str:
    payload = {
        "sub": user_id,
        "role": role,
        "campaign_id": campaign_id,
        "exp": datetime.utcnow() + timedelta(hours=JWT_EXPIRATION_HOURS),
        "iat": datetime.utcnow()
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def decode_jwt(token: str) -> Dict:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expiré")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Token invalide")

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> Dict:
    token = credentials.credentials
    payload = decode_jwt(token)
    return payload

async def require_role(allowed_roles: List[str]):
    async def role_checker(current_user: Dict = Depends(get_current_user)):
        if current_user.get("role") not in allowed_roles:
            raise HTTPException(status_code=403, detail="Permission insuffisante")
        return current_user
    return role_checker

async def get_db(request: Request):
    return request.app.state.db

# ============================================================
# ROUTES — AUTHENTIFICATION
# ============================================================

@app.post("/api/v1/auth/register", response_model=UserResponse, status_code=201)
async def register(user: UserRegister, db=Depends(get_db)):
    """Inscription d'un nouvel utilisateur"""

    # Vérifier si le téléphone existe déjà
    existing = await db.fetchrow("SELECT id FROM users WHERE phone = $1", user.phone)
    if existing:
        raise HTTPException(status_code=400, detail="Ce numéro de téléphone est déjà enregistré")

    # Hasher le PIN
    pin_hash = hash_pin(user.pin)

    # Générer NGD ID
    ngd_id = await db.fetchval("SELECT generate_ngd_id()")

    # Créer l'utilisateur
    query = """
        INSERT INTO users (phone, first_name, last_name, email, pin_hash, 
                          profile_type, region, commune, specialty, ngd_id, status)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 'active')
        RETURNING id, phone, first_name, last_name, email, role, profile_type,
                  region, commune, ngd_id, wallet_balance, cashback_balance, status, created_at
    """
    row = await db.fetchrow(query, user.phone, user.first_name, user.last_name,
                            user.email, pin_hash, user.profile_type, user.region,
                            user.commune, user.specialty, ngd_id)

    # Logger
    await db.execute("""
        SELECT log_activity($1, NULL, 'inscription', 'user', 
                           $2::jsonb, 'user', $1, 'api')
    """, row["id"], json.dumps({"profile_type": user.profile_type, "region": user.region}))

    return dict(row)

@app.post("/api/v1/auth/login")
async def login(credentials: UserLogin, db=Depends(get_db)):
    """Connexion avec téléphone + PIN"""

    row = await db.fetchrow("""
        SELECT id, phone, first_name, last_name, role, pin_hash, status
        FROM users WHERE phone = $1
    """, credentials.phone)

    if not row or not verify_pin(credentials.pin, row["pin_hash"]):
        raise HTTPException(status_code=401, detail="Téléphone ou PIN incorrect")

    if row["status"] != "active":
        raise HTTPException(status_code=403, detail="Compte suspendu")

    # Mettre à jour last_active
    await db.execute("UPDATE users SET last_active = NOW() WHERE id = $1", row["id"])

    token = create_jwt(str(row["id"]), row["role"])

    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "id": str(row["id"]),
            "phone": row["phone"],
            "first_name": row["first_name"],
            "last_name": row["last_name"],
            "role": row["role"]
        }
    }

@app.get("/api/v1/auth/me", response_model=UserResponse)
async def get_me(current_user: Dict = Depends(get_current_user), db=Depends(get_db)):
    """Profil de l'utilisateur connecté"""

    row = await db.fetchrow("""
        SELECT id, phone, first_name, last_name, email, role, profile_type,
               region, commune, ngd_id, wallet_balance, cashback_balance, status, created_at
        FROM users WHERE id = $1
    """, current_user["sub"])

    if not row:
        raise HTTPException(status_code=404, detail="Utilisateur non trouvé")

    return dict(row)

# ============================================================
# ROUTES — CAMPAGNES
# ============================================================

@app.post("/api/v1/campaigns", response_model=CampaignResponse, status_code=201)
async def create_campaign(
    campaign: CampaignCreate,
    current_user: Dict = Depends(require_role(["superadmin", "admin"])),
    db=Depends(get_db)
):
    """Créer une nouvelle campagne"""

    # Générer le slug
    slug = campaign.name.lower().replace(" ", "-").replace("_", "-")[:100]
    base_slug = slug
    counter = 1
    while await db.fetchval("SELECT 1 FROM campaigns WHERE slug = $1", slug):
        slug = f"{base_slug}-{counter}"
        counter += 1

    query = """
        INSERT INTO campaigns (name, slug, election_type, region, commune, 
                              election_date, owner_id, status, description)
        VALUES ($1, $2, $3, $4, $5, $6, $7, 'active', $8)
        RETURNING id, name, slug, election_type, region, commune, 
                  election_date::text, status, owner_id::text, created_at
    """
    row = await db.fetchrow(query, campaign.name, slug, campaign.election_type,
                            campaign.region, campaign.commune, campaign.election_date,
                            current_user["sub"], campaign.description)

    # Logger
    await db.execute("""
        SELECT log_activity($1, $2, 'creation_campagne', 'campaign',
                           $3::jsonb, 'campaign', $2, 'api')
    """, current_user["sub"], row["id"], json.dumps({"name": campaign.name}))

    return dict(row)

@app.get("/api/v1/campaigns", response_model=List[CampaignResponse])
async def list_campaigns(
    status: Optional[str] = None,
    region: Optional[str] = None,
    current_user: Dict = Depends(get_current_user),
    db=Depends(get_db)
):
    """Lister les campagnes (filtrable)"""

    query = "SELECT id, name, slug, election_type, region, commune, election_date::text, status, owner_id::text, created_at FROM campaigns WHERE 1=1"
    params = []

    if status:
        query += f" AND status = ${len(params)+1}"
        params.append(status)
    if region:
        query += f" AND region = ${len(params)+1}"
        params.append(region)

    # Si pas superadmin, ne voir que ses campagnes ou celles où il est membre
    if current_user.get("role") not in ["superadmin", "admin"]:
        query += f" AND (owner_id = ${len(params)+1} OR id IN (SELECT campaign_id FROM team_members WHERE user_id = ${len(params)+1}))"
        params.append(current_user["sub"])

    query += " ORDER BY created_at DESC"

    rows = await db.fetch(query, *params)
    return [dict(r) for r in rows]

@app.get("/api/v1/campaigns/{campaign_id}", response_model=CampaignResponse)
async def get_campaign(campaign_id: str, current_user: Dict = Depends(get_current_user), db=Depends(get_db)):
    """Détail d'une campagne"""

    row = await db.fetchrow("""
        SELECT id, name, slug, election_type, region, commune, 
               election_date::text, status, owner_id::text, created_at
        FROM campaigns WHERE id = $1
    """, campaign_id)

    if not row:
        raise HTTPException(status_code=404, detail="Campagne non trouvée")

    return dict(row)

@app.get("/api/v1/campaigns/{campaign_id}/stats")
async def get_campaign_stats(campaign_id: str, current_user: Dict = Depends(get_current_user), db=Depends(get_db)):
    """Statistiques d'une campagne"""

    row = await db.fetchrow("SELECT * FROM v_campaign_stats WHERE campaign_id = $1", campaign_id)
    if not row:
        raise HTTPException(status_code=404, detail="Campagne non trouvée")

    return dict(row)

# ============================================================
# ROUTES — GESTION D'ÉQUIPE
# ============================================================

@app.post("/api/v1/campaigns/{campaign_id}/team/invite", response_model=TeamMemberResponse, status_code=201)
async def invite_team_member(
    campaign_id: str,
    invite: TeamMemberInvite,
    current_user: Dict = Depends(require_role(["superadmin", "admin", "manager"])),
    db=Depends(get_db)
):
    """Inviter un membre dans l'équipe"""

    # Vérifier que la campagne existe
    campaign = await db.fetchrow("SELECT id FROM campaigns WHERE id = $1", campaign_id)
    if not campaign:
        raise HTTPException(status_code=404, detail="Campagne non trouvée")

    # Trouver ou créer l'utilisateur
    user_id = None
    if invite.user_id:
        user = await db.fetchrow("SELECT id FROM users WHERE id = $1", invite.user_id)
        if user:
            user_id = user["id"]
    elif invite.phone:
        user = await db.fetchrow("SELECT id FROM users WHERE phone = $1", invite.phone)
        if user:
            user_id = user["id"]

    if not user_id:
        raise HTTPException(status_code=400, detail="Utilisateur non trouvé. Il doit d'abord s'inscrire.")

    # Vérifier qu'il n'est pas déjà membre
    existing = await db.fetchrow("""
        SELECT id FROM team_members WHERE campaign_id = $1 AND user_id = $2
    """, campaign_id, user_id)
    if existing:
        raise HTTPException(status_code=400, detail="Cet utilisateur est déjà membre de l'équipe")

    query = """
        INSERT INTO team_members (campaign_id, user_id, role, invited_by, status)
        VALUES ($1, $2, $3, $4, 'pending')
        RETURNING id, campaign_id::text, user_id::text, role, permissions, status, invited_at
    """
    row = await db.fetchrow(query, campaign_id, user_id, invite.role, current_user["sub"])

    # Logger
    await db.execute("""
        SELECT log_activity($1, $2, 'invitation_equipe', 'team',
                           $3::jsonb, 'team_member', $4, 'api')
    """, current_user["sub"], campaign_id, 
        json.dumps({"invited_user": str(user_id), "role": invite.role}), row["id"])

    return dict(row)

@app.get("/api/v1/campaigns/{campaign_id}/team", response_model=List[TeamMemberResponse])
async def list_team_members(
    campaign_id: str,
    current_user: Dict = Depends(get_current_user),
    db=Depends(get_db)
):
    """Lister les membres de l'équipe"""

    rows = await db.fetch("""
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

    return [dict(r) for r in rows]

@app.put("/api/v1/team-members/{member_id}/role")
async def update_team_member_role(
    member_id: str,
    role: str,
    current_user: Dict = Depends(require_role(["superadmin", "admin", "manager"])),
    db=Depends(get_db)
):
    """Modifier le rôle d'un membre"""

    await db.execute("""
        UPDATE team_members SET role = $1, updated_at = NOW() WHERE id = $2
    """, role, member_id)

    return {"message": "Rôle mis à jour"}

@app.put("/api/v1/team-members/{member_id}/permissions")
async def update_team_member_permissions(
    member_id: str,
    permissions: Dict[str, bool],
    current_user: Dict = Depends(require_role(["superadmin", "admin"])),
    db=Depends(get_db)
):
    """Modifier les permissions d'un membre"""

    await db.execute("""
        UPDATE team_members SET permissions = $1, updated_at = NOW() WHERE id = $2
    """, json.dumps(permissions), member_id)

    return {"message": "Permissions mises à jour"}

# ============================================================
# ROUTES — UTILISATEURS
# ============================================================

@app.get("/api/v1/users", response_model=List[UserResponse])
async def list_users(
    campaign_id: Optional[str] = None,
    profile_type: Optional[str] = None,
    region: Optional[str] = None,
    status: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    current_user: Dict = Depends(get_current_user),
    db=Depends(get_db)
):
    """Lister les utilisateurs (avec filtres et recherche)"""

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

    rows = await db.fetch(query, *params)
    return [dict(r) for r in rows]

@app.get("/api/v1/users/{user_id}/history")
async def get_user_history(
    user_id: str,
    limit: int = Query(50, ge=1, le=200),
    current_user: Dict = Depends(get_current_user),
    db=Depends(get_db)
):
    """Historique complet d'un utilisateur"""

    # Vérifier les permissions
    if current_user["sub"] != user_id and current_user.get("role") not in ["superadmin", "admin", "manager"]:
        raise HTTPException(status_code=403, detail="Permission insuffisante")

    rows = await db.fetch("""
        SELECT id, action_type, action_category, action_details, source, created_at
        FROM activity_logs
        WHERE user_id = $1
        ORDER BY created_at DESC
        LIMIT $2
    """, user_id, limit)

    return [dict(r) for r in rows]

# ============================================================
# ROUTES — COMMANDES TCL
# ============================================================

@app.post("/api/v1/orders", response_model=OrderResponse, status_code=201)
async def create_order(
    order: OrderCreate,
    current_user: Dict = Depends(get_current_user),
    db=Depends(get_db)
):
    """Créer une commande TCL"""

    # Calculer le total
    total = sum(item.get("montant", 0) * item.get("qte", 1) for item in order.items)

    # Cashback
    cashback_comm = round(total * 0.025) if total >= 30000 else 0
    cashback_col = round(total * 0.01) if total >= 30000 else 0

    order_number = await db.fetchval("SELECT generate_order_number()")

    query = """
        INSERT INTO tcl_orders (order_number, user_id, items, total_amount,
                               cashback_community, cashback_colistier, 
                               delivery_mode, address, region, commune, status)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 'pending')
        RETURNING id, order_number, total_amount, status, payment_status, created_at
    """
    row = await db.fetchrow(query, order_number, current_user["sub"], 
                            json.dumps(order.items), total, cashback_comm, cashback_col,
                            order.delivery_mode, order.address, order.region, order.commune)

    # Logger
    await db.execute("""
        SELECT log_activity($1, NULL, 'creation_commande', 'order',
                           $2::jsonb, 'order', $3, 'api')
    """, current_user["sub"], json.dumps({"order_number": order_number, "total": total}), row["id"])

    return dict(row)

@app.get("/api/v1/orders")
async def list_orders(
    campaign_id: Optional[str] = None,
    status: Optional[str] = None,
    payment_status: Optional[str] = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    current_user: Dict = Depends(get_current_user),
    db=Depends(get_db)
):
    """Lister les commandes"""

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

    rows = await db.fetch(query, *params)
    return [dict(r) for r in rows]

# ============================================================
# ROUTES — WALLET MI SIKAH
# ============================================================

@app.post("/api/v1/wallet/deposit")
async def deposit(
    amount: int = Field(..., gt=0),
    reference: Optional[str] = None,
    current_user: Dict = Depends(get_current_user),
    db=Depends(get_db)
):
    """Déposer sur le wallet"""

    tx_number = await db.fetchval("SELECT generate_transaction_number()")

    async with db.acquire() as conn:
        async with conn.transaction():
            # Mettre à jour le solde
            await conn.execute("""
                UPDATE users SET wallet_balance = wallet_balance + $1 WHERE id = $2
            """, amount, current_user["sub"])

            # Créer la transaction
            await conn.execute("""
                INSERT INTO wallet_transactions (transaction_number, user_id, type, amount,
                                                description, reference, balance_after)
                VALUES ($1, $2, 'deposit', $3, 'Dépôt Mi Sikah', $4,
                       (SELECT wallet_balance FROM users WHERE id = $2))
            """, tx_number, current_user["sub"], amount, reference)

    return {"message": "Dépôt effectué", "transaction_number": tx_number, "amount": amount}

@app.post("/api/v1/wallet/withdraw", response_model=WithdrawalResponse, status_code=201)
async def request_withdrawal(
    req: WithdrawalRequest,
    current_user: Dict = Depends(get_current_user),
    db=Depends(get_db)
):
    """Demander un retrait"""

    # Vérifier le solde
    user = await db.fetchrow("SELECT wallet_balance FROM users WHERE id = $1", current_user["sub"])
    if not user or user["wallet_balance"] < req.amount:
        raise HTTPException(status_code=400, detail="Solde insuffisant")

    tx_number = await db.fetchval("SELECT generate_transaction_number()")

    query = """
        INSERT INTO wallet_transactions (transaction_number, user_id, type, amount,
                                        description, withdrawal_status)
        VALUES ($1, $2, 'withdrawal', $3, $4, 'pending')
        RETURNING id, transaction_number, amount, withdrawal_status, created_at
    """
    row = await db.fetchrow(query, tx_number, current_user["sub"], req.amount, req.description or "Retrait Mi Sikah")

    return dict(row)

@app.get("/api/v1/wallet/withdrawals/pending")
async def list_pending_withdrawals(
    current_user: Dict = Depends(require_role(["superadmin", "admin", "agent_croire"])),
    db=Depends(get_db)
):
    """Lister les retraits en attente (Agent CROIRE)"""

    rows = await db.fetch("SELECT * FROM v_pending_withdrawals")
    return [dict(r) for r in rows]

@app.post("/api/v1/wallet/withdrawals/{tx_id}/validate")
async def validate_withdrawal(
    tx_id: str,
    current_user: Dict = Depends(require_role(["superadmin", "admin", "agent_croire"])),
    db=Depends(get_db)
):
    """Valider un retrait"""

    async with db.acquire() as conn:
        async with conn.transaction():
            tx = await conn.fetchrow("""
                SELECT user_id, amount FROM wallet_transactions 
                WHERE id = $1 AND type = 'withdrawal' AND withdrawal_status = 'pending'
            """, tx_id)

            if not tx:
                raise HTTPException(status_code=404, detail="Transaction non trouvée ou déjà traitée")

            # Déduire le solde
            await conn.execute("""
                UPDATE users SET wallet_balance = wallet_balance - $1 WHERE id = $2
            """, tx["amount"], tx["user_id"])

            # Mettre à jour la transaction
            await conn.execute("""
                UPDATE wallet_transactions 
                SET withdrawal_status = 'approved', processed_by = $1, processed_at = NOW()
                WHERE id = $2
            """, current_user["sub"], tx_id)

    return {"message": "Retrait validé"}

# ============================================================
# ROUTES — CONFIGURATION
# ============================================================

@app.get("/api/v1/config/{key}")
async def get_config(key: str, db=Depends(get_db)):
    """Récupérer une configuration"""

    row = await db.fetchrow("SELECT config_key, config_value, config_type FROM system_config WHERE config_key = $1", key)
    if not row:
        raise HTTPException(status_code=404, detail="Configuration non trouvée")

    return dict(row)

@app.put("/api/v1/config/{key}")
async def update_config(
    key: str,
    config: ConfigUpdate,
    current_user: Dict = Depends(require_role(["superadmin", "admin"])),
    db=Depends(get_db)
):
    """Mettre à jour une configuration"""

    await db.execute("""
        INSERT INTO system_config (config_key, config_value, config_type, updated_by)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (config_key) 
        DO UPDATE SET config_value = $2, config_type = $3, updated_by = $4, updated_at = NOW()
    """, key, config.config_value, config.config_type, current_user["sub"])

    return {"message": "Configuration mise à jour"}

@app.get("/api/v1/config")
async def list_configs(db=Depends(get_db)):
    """Lister toutes les configurations"""

    rows = await db.fetch("SELECT config_key, config_value, config_type, description FROM system_config ORDER BY config_key")
    return [dict(r) for r in rows]

# ============================================================
# ROUTES — HISTORIQUE / ACTIVITÉ
# ============================================================

@app.post("/api/v1/activity-logs")
async def get_activity_logs(
    filters: ActivityLogFilter,
    current_user: Dict = Depends(get_current_user),
    db=Depends(get_db)
):
    """Récupérer les logs d'activité (filtrables)"""

    query = """
        SELECT al.id, al.action_type, al.action_category, al.action_details,
               al.source, al.created_at,
               u.first_name || ' ' || u.last_name as user_name, u.phone as user_phone
        FROM activity_logs al
        LEFT JOIN users u ON al.user_id = u.id
        WHERE 1=1
    """
    params = []

    if filters.action_type:
        query += f" AND al.action_type = ${len(params)+1}"
        params.append(filters.action_type)
    if filters.action_category:
        query += f" AND al.action_category = ${len(params)+1}"
        params.append(filters.action_category)
    if filters.user_id:
        query += f" AND al.user_id = ${len(params)+1}"
        params.append(filters.user_id)
    if filters.date_from:
        query += f" AND al.created_at >= ${len(params)+1}"
        params.append(filters.date_from)
    if filters.date_to:
        query += f" AND al.created_at <= ${len(params)+1}"
        params.append(filters.date_to)

    query += f" ORDER BY al.created_at DESC LIMIT ${len(params)+1} OFFSET ${len(params)+2}"
    params.extend([filters.limit, filters.offset])

    rows = await db.fetch(query, *params)
    return [dict(r) for r in rows]

# ============================================================
# ROUTES — HEALTH & INFO
# ============================================================

@app.get("/")
async def root():
    return {
        "name": "Coalition 509 API",
        "version": "1.0.0",
        "status": "operational",
        "ecosystem": "VoteConnect | ChallengeFinancier™",
        "author": "Coach Morgan's (Simplice KOUAME)"
    }

@app.get("/health")
async def health(db=Depends(get_db)):
    try:
        await db.fetchval("SELECT 1")
        return {"status": "healthy", "database": "connected", "timestamp": datetime.utcnow().isoformat()}
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Database error: {str(e)}")

@app.get("/api/v1/dashboard/stats")
async def dashboard_stats(current_user: Dict = Depends(get_current_user), db=Depends(get_db)):
    """Stats globales pour le dashboard"""

    stats = await db.fetchrow("""
        SELECT 
            (SELECT COUNT(*) FROM users WHERE status = 'active') as total_users,
            (SELECT COUNT(*) FROM campaigns WHERE status = 'active') as total_campaigns,
            (SELECT COUNT(*) FROM tcl_orders) as total_orders,
            (SELECT COALESCE(SUM(total_amount), 0) FROM tcl_orders WHERE payment_status = 'paid') as total_revenue,
            (SELECT COUNT(*) FROM coalition_groups WHERE status = 'active') as total_groups,
            (SELECT COUNT(*) FROM lms_enrollments) as total_lms,
            (SELECT COUNT(*) FROM wallet_transactions WHERE type = 'withdrawal' AND withdrawal_status = 'pending') as pending_withdrawals
    """)

    return dict(stats)

# ============================================================
# DÉMARRAGE
# ============================================================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", 8000)))
