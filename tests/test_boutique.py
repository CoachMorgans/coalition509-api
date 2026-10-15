# Banc d'essai v2.11.0 — Boutique sécurisée (Wave vérifié) + Candidats Têtes de liste — base SQLite temporaire
import os, sys, tempfile, importlib, pytest
D = tempfile.mkdtemp()
os.environ['DATABASE_URL'] = 'sqlite:///' + os.path.join(D, 't.db')
os.environ['SECRET_KEY'] = 'cle-de-test-boutique-0123456789'
os.environ['GESTIONNAIRES_BOUTIQUE'] = '+225 07 00 00 00 01, 0022507 00 00 00 09'
os.environ['STATS_KEY'] = 'stats-cle-de-test-0123456789'
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
api = importlib.import_module('coalition509_api')
app, db = api.app, api.db

@pytest.fixture(scope='module')
def ctx():
    c = app.test_client()
    with app.app_context():
        def u(phone, role, prenom):
            x = api.User(phone=api.normaliser_tel(phone), pin_hash=api.hash_pin('1234'), first_name=prenom, last_name='T', role=role, status='active', ngd_id=api.generate_ngd_id())
            db.session.add(x); db.session.commit(); return x
        g = u('+2250700000001', 'admin', 'Morgan')       # Gestionnaire VoteConnect
        a = u('+2250700000002', 'admin', 'CandidatA')    # Tête de liste
        b = u('+2250700000003', 'admin', 'CandidatB')
        cit = u('+2250700000004', 'user', 'Citoyen')
        tok = {k: api.make_session_token(v) for k, v in dict(g=g, a=a, b=b, cit=cit).items()}
    H = lambda k: {'Authorization': 'Bearer ' + tok[k]}
    return c, H

def j(r): return r.get_json()

def test_parcours_complet(ctx):
    c, H = ctx
    # Profil : drapeaux pour le tableau de bord
    me = j(c.get('/api/auth/me', headers=H('g')))['user']; assert me['gestionnaire'] and me['acheteur']
    me = j(c.get('/api/auth/me', headers=H('a')))['user']; assert me['acheteur'] and not me['gestionnaire']
    me = j(c.get('/api/auth/me', headers=H('cit')))['user']; assert not me['acheteur']
    # Catalogue : Gestionnaire seul
    assert c.post('/api/shop/products', json={'name': 'T-Shirt', 'price': 5000, 'stock_quantity': 10}, headers=H('a')).status_code == 403
    r = c.post('/api/shop/suppliers', json={'name': 'Fournisseur Test', 'contact_name': 'Kone', 'phone': '0102030405'}, headers=H('g')); assert r.status_code == 201
    sid = j(r)['supplier']['id']
    pid = j(c.post('/api/shop/products', json={'name': 'T-Shirt', 'price': 5000, 'stock_quantity': 10, 'supplier_id': sid}, headers=H('g')))['product']['id']
    pid2 = j(c.post('/api/shop/products', json={'name': 'Casquette', 'price': 3000, 'stock_quantity': 2}, headers=H('g')))['product']['id']
    # Citoyen : aucun accès
    for url in ('/api/shop/products', '/api/shop/cart', '/api/shop/orders'):
        assert c.get(url, headers=H('cit')).status_code == 403
    assert c.post('/api/shop/cart/add', json={'product_id': pid, 'quantity': 1}, headers=H('cit')).status_code == 403
    # Candidat A : panier, contrôle du stock
    assert c.post('/api/shop/cart/add', json={'product_id': pid2, 'quantity': 3}, headers=H('a')).status_code == 409
    assert c.post('/api/shop/cart/add', json={'product_id': pid, 'quantity': 2}, headers=H('a')).status_code == 200
    r = c.post('/api/shop/orders/create', json={}, headers=H('a')); assert r.status_code == 201
    o = j(r); oid = o['order']['id']
    assert o['order']['total_amount'] == 10000
    assert o['wave_url'] == 'https://pay.wave.com/m/M_ci_QlW5ke-hYGbA/c/ci/?amount=10000'
    with app.app_context():
        assert db.session.get(api.Product, pid).stock_quantity == 10, 'stock intact tant que non payé'
        assert api.Delivery.query.filter_by(order_id=oid).first().status == 'awaiting_payment'
        assert api.Invoice.query.filter_by(order_id=oid).first().status == 'pending'
    # Portes fermées
    for url in ('/api/orders/pay', '/api/v1/payments/init', '/api/v1/payments/confirm'):
        r = c.post(url, json={'id': oid, 'payment_method': 'stripe'}, headers=H('a')); assert r.status_code == 410, url
    assert c.post('/api/shop/orders/update', json={'id': oid, 'status': 'completed', 'payment_status': 'paid'}, headers=H('a')).status_code == 403
    assert c.post('/api/shop/orders/update', json={'id': oid, 'status': 'completed'}, headers=H('g')).status_code == 409
    inv_id = j(c.get('/api/shop/invoices', headers=H('a')))['invoices'][0]['id']
    assert c.post('/api/shop/invoices/update', json={'id': inv_id, 'status': 'paid'}, headers=H('g')).status_code == 409
    dl_id = j(c.get('/api/shop/deliveries', headers=H('a')))['deliveries'][0]['id']
    assert c.post('/api/shop/deliveries/update', json={'id': dl_id, 'status': 'shipped'}, headers=H('g')).status_code == 409
    with app.app_context():
        assert db.session.get(api.Order, oid).payment_status == 'pending'
    # Candidat B ne voit pas la commande de A
    assert j(c.get('/api/shop/orders', headers=H('b')))['total'] == 0
    assert c.get(f'/api/shop/orders/detail?id={oid}', headers=H('b')).status_code == 404
    assert c.post('/api/shop/orders/declare-payment', json={'id': oid, 'reference': 'TABCDEF123'}, headers=H('b')).status_code == 404
    assert j(c.get('/api/orders', headers=H('b')))['total'] == 0
    # Déclaration de la référence Wave
    assert c.post('/api/shop/orders/declare-payment', json={'id': oid, 'reference': 'ab'}, headers=H('a')).status_code == 400
    r = c.post('/api/shop/orders/declare-payment', json={'id': oid, 'reference': 't_ab12-cd34 ef'}, headers=H('a')); assert r.status_code == 200
    assert j(r)['order']['wave_reference'] == 'TAB12CD34EF' and j(r)['order']['payment_status'] == 'declared'
    assert c.post('/api/shop/orders/declare-payment', json={'id': oid, 'reference': 'TAUTRE12345'}, headers=H('a')).status_code == 409
    assert c.post('/api/shop/orders/cancel', json={'id': oid}, headers=H('a')).status_code == 409
    # Le candidat ne valide pas son propre paiement
    assert c.post('/api/shop/orders/validate-payment', json={'id': oid, 'decision': 'valider'}, headers=H('a')).status_code == 403
    # B réutilise la même référence : refusé
    c.post('/api/shop/cart/add', json={'product_id': pid, 'quantity': 1}, headers=H('b'))
    oid_b = j(c.post('/api/shop/orders/create', json={}, headers=H('b')))['order']['id']
    assert c.post('/api/shop/orders/declare-payment', json={'id': oid_b, 'reference': 'TAB12CD34EF'}, headers=H('b')).status_code == 409
    # Gestionnaire : liste « à vérifier », rejet puis nouvelle référence puis validation
    lst = j(c.get('/api/shop/orders?payment_status=declared', headers=H('g'))); assert lst['a_verifier'] == 1 and lst['total'] == 1
    r = c.post('/api/shop/orders/validate-payment', json={'id': oid, 'decision': 'rejeter', 'motif': 'introuvable dans Wave'}, headers=H('g'))
    assert r.status_code == 200 and j(r)['order']['payment_status'] == 'rejected' and 'introuvable' in j(r)['order']['payment_note']
    assert j(r)['order']['wave_url'].endswith('amount=10000')
    assert c.post('/api/shop/orders/declare-payment', json={'id': oid, 'reference': 'TVRAIE99887'}, headers=H('a')).status_code == 200
    r = c.post('/api/shop/orders/validate-payment', json={'id': oid, 'decision': 'valider'}, headers=H('g'))
    assert r.status_code == 200 and j(r)['order']['payment_status'] == 'paid' and j(r)['order']['status'] == 'confirmed'
    with app.app_context():
        assert db.session.get(api.Product, pid).stock_quantity == 8, 'stock retiré à la validation'
        assert api.StockMovement.query.filter_by(product_id=pid, movement_type='out').count() == 1
        inv = api.Invoice.query.filter_by(order_id=oid).first(); assert inv.status == 'paid' and inv.paid_at
        assert api.Delivery.query.filter_by(order_id=oid).first().status == 'pending'
    assert c.post('/api/shop/orders/validate-payment', json={'id': oid, 'decision': 'valider'}, headers=H('g')).status_code == 409
    # Après paiement : suivi de livraison possible, suppression interdite
    assert c.post('/api/shop/deliveries/update', json={'id': dl_id, 'status': 'shipped', 'tracking_number': 'C509-1'}, headers=H('g')).status_code == 200
    assert c.post('/api/shop/orders/update', json={'id': oid, 'status': 'delivered'}, headers=H('g')).status_code == 200
    assert c.post('/api/shop/orders/delete', json={'id': oid}, headers=H('g')).status_code == 409
    # B annule sa commande non payée
    r = c.post('/api/shop/orders/cancel', json={'id': oid_b}, headers=H('b')); assert r.status_code == 200 and j(r)['order']['payment_status'] == 'cancelled'
    # Guichet Hub Partenaires : la vente payée est comptée
    import datetime
    jour = datetime.date.today().isoformat()
    st = j(c.get(f'/api/stats-partenaires?du={jour}&au={jour}', headers={'X-Stats-Key': os.environ['STATS_KEY']}))
    assert st['ok'] and sum(l['brut'] for l in st['lignes']) == 10000 and st['version'] == '2.11.1'
    assert st['indicateurs']['Paiements Wave à vérifier'] == 0
    racine = j(c.get('/'))
    assert racine['version'] == '2.11.1' and racine['boutique']['gestionnaires_configures'] == 6

def test_produit_vendu_retire_sans_casser_historique(ctx):
    c, H = ctx
    pid = j(c.get('/api/shop/products', headers=H('g')))['products'][-1]['id']
    r = c.post('/api/shop/products/delete', json={'id': pid}, headers=H('g'))
    assert r.status_code == 200

def test_non_regression_routes_existantes(ctx):
    c, H = ctx
    r = c.post('/api/v1/auth/login', json={'phone': '+225 07 00 00 00 02', 'pin': '1234'})
    assert r.status_code == 200 and j(r)['user']['acheteur'] is True and j(r)['token']
    assert c.post('/api/auth/login', json={'phone': '+2250700000002', 'pin': '9999'}).status_code == 401
    assert c.get('/api/v1/dashboard/stats', headers=H('a')).status_code == 200
    assert 'declared_orders' in j(c.get('/api/v1/dashboard/stats', headers=H('g')))
    assert c.get('/api/v1/campaigns', headers=H('cit')).status_code == 200
    assert c.get('/api/v1/bot/stats').status_code == 200
    assert c.get('/api/shop/products').status_code == 401

def test_gestionnaire_par_numero_meme_sans_role_admin(ctx):
    c, H = ctx
    r = c.post('/api/auth/register', json={'phone': '+225 0700000009', 'pin': '4321', 'first_name': 'Coach', 'last_name': 'Morgans'})
    assert r.status_code == 201
    u = j(r)['user']; assert u['role'] == 'user' and u['gestionnaire'] is True and u['acheteur'] is True
    tok = j(r)['token']
    assert c.get('/api/shop/orders', headers={'Authorization': 'Bearer ' + tok}).status_code == 200
    r2 = c.post('/api/auth/register', json={'phone': '+225 0700000010', 'pin': '4321', 'first_name': 'Simple', 'last_name': 'Citoyen'})
    assert j(r2)['user']['gestionnaire'] is False and j(r2)['user']['acheteur'] is False

# ── v2.11.0 : Promouvoir Candidat Tête de liste ─────────────────────────────
def test_annuaire_reserve(ctx):
    c, H = ctx
    for url in ('/api/users', '/api/v1/users', '/api/v1/export/users'):
        assert c.get(url, headers=H('cit')).status_code == 403, url
    assert c.get('/api/v1/users', headers=H('a')).status_code == 200
    assert c.get('/api/v1/export/users', headers=H('a')).status_code == 403
    r = c.get('/api/v1/export/users', headers=H('g')); assert r.status_code == 200 and b'Phone' in r.data
    d = j(c.get('/api/v1/users?limit=50', headers=H('g'))); assert d['per_page'] == 50 and d['total'] >= 4
    assert j(c.get('/api/v1/users?limit=999', headers=H('g')))['per_page'] == 200
    assert all(u['role'] == 'admin' for u in j(c.get('/api/v1/users?role=admin&limit=200', headers=H('g')))['users'])

def test_promouvoir_puis_retirer_candidat(ctx):
    c, H = ctx
    r = c.post('/api/auth/register', json={'phone': '+225 0700000020', 'pin': '4321', 'first_name': 'Awa', 'last_name': 'Koné'})
    nid = j(r)['user']['id']; T = {'Authorization': 'Bearer ' + j(r)['token']}
    assert c.get('/api/shop/products', headers=T).status_code == 403
    ok = {'user_id': nid, 'candidature': 'Coalition Bélier — Conseil Régional', 'confirme': True}
    # Seul le Gestionnaire peut promouvoir
    for k in ('a', 'cit'):
        assert c.post('/api/users/promote', json=ok, headers=H(k)).status_code == 403
    assert c.post('/api/users/promote', json={**ok, 'candidature': ' x '}, headers=H('g')).status_code == 400
    assert c.post('/api/users/promote', json={**ok, 'confirme': 'true'}, headers=H('g')).status_code == 400
    assert c.post('/api/users/promote', json={**ok, 'user_id': 999999}, headers=H('g')).status_code == 404
    r = c.post('/api/users/promote', json=ok, headers=H('g')); assert r.status_code == 200, j(r)
    assert j(r)['user']['tete_de_liste'] and j(r)['user']['candidature'] == 'Coalition Bélier — Conseil Régional'
    # Effet immédiat, sans se reconnecter
    me = j(c.get('/api/auth/me', headers=T))['user']; assert me['acheteur'] and me['role'] == 'admin' and me['candidature']
    assert c.get('/api/shop/products', headers=T).status_code == 200
    assert c.post('/api/users/promote', json=ok, headers=H('g')).status_code == 409
    r = c.post('/api/users/promote', json={**ok, 'candidature': 'Coalition Bélier   —  Toumodi'}, headers=H('g'))
    assert r.status_code == 200 and j(r)['user']['candidature'] == 'Coalition Bélier — Toumodi'
    lst = j(c.get('/api/v1/users?role=admin&search=Toumodi', headers=H('g')))['users']; assert [u['id'] for u in lst] == [nid]
    # Une commande déclarée avant le retrait reste validable par le Gestionnaire
    pid = j(c.post('/api/shop/products', json={'name': 'Badge', 'price': 100, 'stock_quantity': 5}, headers=H('g')))['product']['id']
    assert c.post('/api/shop/cart/add', json={'product_id': pid, 'quantity': 1}, headers=T).status_code == 200
    oid = j(c.post('/api/shop/orders/create', json={}, headers=T))['order']['id']
    assert c.post('/api/shop/orders/declare-payment', json={'id': oid, 'reference': 'TAWA100REF'}, headers=T).status_code == 200
    # Retrait du statut
    assert c.post('/api/users/demote', json={'user_id': nid, 'motif': 'fin de candidature'}, headers=H('a')).status_code == 403
    assert c.post('/api/users/demote', json={'user_id': nid}, headers=H('g')).status_code == 400
    ids = {k: j(c.get('/api/auth/me', headers=H(k)))['user']['id'] for k in ('g', 'cit')}
    assert c.post('/api/users/demote', json={'user_id': ids['g'], 'motif': 'essai'}, headers=H('g')).status_code == 409
    assert c.post('/api/users/demote', json={'user_id': ids['cit'], 'motif': 'essai'}, headers=H('g')).status_code == 409
    r = c.post('/api/users/demote', json={'user_id': nid, 'motif': 'Liste non retenue'}, headers=H('g'))
    assert r.status_code == 200 and '1 paiement(s)' in j(r)['message'] and j(r)['user']['role'] == 'user' and not j(r)['user']['candidature']
    assert c.get('/api/shop/products', headers=T).status_code == 403
    assert j(c.get('/api/auth/me', headers=T))['user']['acheteur'] is False
    assert c.post('/api/shop/orders/validate-payment', json={'id': oid, 'decision': 'valider'}, headers=H('g')).status_code == 200
    # Journal
    assert c.get('/api/users/role-history', headers=H('a')).status_code == 403
    h = j(c.get('/api/users/role-history', headers=H('g')))['history']
    assert [x['action'] for x in h[:3]] == ['retrait', 'mise_a_jour', 'promotion']
    assert h[0]['motif'] == 'Liste non retenue' and h[0]['user'] == 'Awa Koné' and h[0]['par'] == 'Morgan T'

def test_promotion_comptes_proteges(ctx):
    c, H = ctx
    with app.app_context():
        sa = api.User(phone=api.normaliser_tel('+2250700000030'), pin_hash=api.hash_pin('1234'), role='superadmin', status='active', ngd_id=api.generate_ngd_id())
        off = api.User(phone=api.normaliser_tel('+2250700000031'), pin_hash=api.hash_pin('1234'), role='user', status='inactive', ngd_id=api.generate_ngd_id())
        db.session.add_all([sa, off]); db.session.commit(); sid, oid = sa.id, off.id
    p = {'candidature': 'Liste test', 'confirme': True}
    assert c.post('/api/users/promote', json={**p, 'user_id': sid}, headers=H('g')).status_code == 409
    assert c.post('/api/users/promote', json={**p, 'user_id': oid}, headers=H('g')).status_code == 409

def test_export_commandes_cloisonne(ctx):
    c, H = ctx
    tout = c.get('/api/v1/export/orders', headers=H('g')).data.decode().strip().splitlines()
    a = c.get('/api/v1/export/orders', headers=H('a')).data.decode().strip().splitlines()
    cit = c.get('/api/v1/export/orders', headers=H('cit')).data.decode().strip().splitlines()
    assert len(tout) > len(a) > 1 and cit == [tout[0]]

# ── v2.11.0 : comptes officiels VoteConnect et comptes de démonstration ─────
def test_comptes_officiels_admin_et_gestionnaires(ctx):
    c, H = ctx
    assert set(api.COMPTES_OFFICIELS) == {'0707786614', '0767560908', '0787102190', '0505761784'}
    formats = ('0707786614', '+225 07 67 56 09 08', '002250787102190', '225 05 05 76 17 84')
    for i, tel in enumerate(formats):
        r = c.post('/api/auth/register', json={'phone': tel, 'pin': '2580', 'first_name': f'Officiel{i}', 'last_name': 'VC'})
        assert r.status_code == 201, (tel, j(r))
        u = j(r)['user']; assert u['role'] == 'admin' and u['gestionnaire'] and u['acheteur'], (tel, u)
    # Même personne, autre format : connexion OK, pas de doublon
    r = c.post('/api/auth/login', json={'phone': '+2250707786614', 'pin': '2580'}); assert r.status_code == 200 and j(r)['user']['first_name'] == 'Officiel0'
    assert c.post('/api/auth/register', json={'phone': '+225 0707786614', 'pin': '1', 'first_name': 'X', 'last_name': 'Y'}).status_code == 409
    T = {'Authorization': 'Bearer ' + j(r)['token']}
    # Un officiel peut promouvoir, valider… et ne peut pas être retiré
    assert c.get('/api/users/role-history', headers=T).status_code == 200
    oid = next(u['id'] for u in j(c.get('/api/v1/users?search=Officiel1', headers=T))['users'])
    r = c.post('/api/users/demote', json={'user_id': oid, 'motif': 'essai'}, headers=T); assert r.status_code == 409 and 'officiel' in j(r)['message']
    # Rétrogradé directement en base → rétabli à la connexion
    with app.app_context():
        u = db.session.get(api.User, oid); u.role = 'user'; db.session.commit()
    r = c.post('/api/v1/auth/login', json={'phone': '0767560908', 'pin': '2580'}); assert j(r)['user']['role'] == 'admin'
    h = j(c.get('/api/users/role-history', headers=T))['history']
    assert any(x['motif'] == 'Compte officiel VoteConnect (Admin & Gestionnaire)' for x in h)

def test_comptes_demo_neutralises(ctx):
    c, H = ctx
    with app.app_context():
        d = api.User(phone='002250707777701', pin_hash=api.hash_pin('1234'), first_name='Jean', last_name='Kouassi', role='admin', status='active', ngd_id=api.generate_ngd_id())
        db.session.add(d); db.session.commit()
        tok = api.make_session_token(d); did = d.id
    T = {'Authorization': 'Bearer ' + tok}
    assert c.get('/api/shop/products', headers=T).status_code == 200      # avant : accès admin avec le PIN public 1234
    with app.app_context():
        api.preparer_comptes()
        d = db.session.get(api.User, did); assert d.role == 'user' and d.status == 'inactive'
    assert c.get('/api/auth/me', headers=T).status_code == 401           # session ouverte coupée
    assert c.post('/api/auth/login', json={'phone': '+2250707777701', 'pin': '1234'}).status_code == 403
    h = j(c.get('/api/users/role-history', headers=H('g')))['history']
    assert h[0]['motif'] == 'Compte de démonstration désactivé' and h[0]['user'] == 'Jean Kouassi'

def test_seed_conserve_officiels_et_cree_demos_inactifs(ctx):
    c, H = ctx
    os.environ['ADMIN_RESET_KEY'] = 'cle-reset-de-test-0123456789'
    r = c.post('/api/seed', headers={'X-Admin-Reset-Key': os.environ['ADMIN_RESET_KEY']}); assert r.status_code == 200, j(r)
    with app.app_context():
        restants = {api.cle_tel(u.phone): u for u in api.User.query.all()}
        for tel in api.COMPTES_OFFICIELS: assert restants[tel].role == 'admin' and restants[tel].status == 'active'
        demos = [u for k, u in restants.items() if k in set(api.COMPTES_DEMO)]
        assert len(demos) == 9 and all(u.status == 'inactive' and u.role == 'user' for u in demos)
    assert c.post('/api/auth/login', json={'phone': '+2250707777701', 'pin': '1234'}).status_code == 403
    assert c.post('/api/auth/login', json={'phone': '0505761784', 'pin': '2580'}).status_code == 200

def test_compteur_utilisateurs_actifs(ctx):
    c, H = ctx
    with app.app_context():
        db.session.add(api.User(phone='002250700000099', pin_hash=api.hash_pin('1234'), role='user', status='inactive', ngd_id=api.generate_ngd_id()))
        db.session.commit()
        actifs = api.User.query.filter_by(status='active').count(); total = api.User.query.count()
    assert total > actifs
    T = {'Authorization': 'Bearer ' + j(c.post('/api/auth/login', json={'phone': '0505761784', 'pin': '2580'}))['token']}   # compte officiel (conservé par /api/seed)
    assert j(c.get('/api/v1/dashboard/stats', headers=T))['total_users'] == actifs
    assert j(c.get('/api/stats/overview', headers=T))['stats']['total_users'] == actifs
