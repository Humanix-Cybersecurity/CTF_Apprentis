"""
Vulnapp — La Carte au Trésor
20 vulnérabilités OWASP Top 10 pédagogiques.

Chaque vulnérabilité est annotée par un commentaire « # [VULN A0X] ... »
pour que le prof puisse la pointer en classe et que l'élève puisse, après
résolution, lire ce qui aurait dû être fait.

ATTENTION : code DÉLIBÉRÉMENT vulnérable. NE JAMAIS exposer sur Internet,
ni hors de la machine de l'élève. Confiné à `localhost` / un conteneur Docker.
"""
import base64
import hashlib
import hmac
import json
import os
import pickle
import random
import re
import sqlite3
import threading
import time
import traceback

import requests
from flask import (Flask, abort, flash, jsonify, make_response, redirect,
                   render_template, render_template_string, request, Response,
                   session, url_for)

from flags import all_flags, STUDENT_ID

# ---------------------------------------------------------------------------
# Bootstrap
# ---------------------------------------------------------------------------
app = Flask(__name__)
# # [VULN A02] secret_key en clair dans le code — un attaquant peut forger les cookies de session
app.secret_key = "treasure-map-not-so-secret"

FLAGS = all_flags()
# Le flag SSTI est exposé volontairement via app.config (challenge #18)
app.config["FLAG_SSTI"] = FLAGS[18]
# Le flag eval() est accessible via app.config (challenge #28)
app.config["FLAG_CALC"] = FLAGS[28]

DB_PATH = os.environ.get("DB_PATH", "/app/data/vulnapp.sqlite")
DATA_DIR = os.path.dirname(DB_PATH)
APP_ROOT = os.path.dirname(os.path.abspath(__file__))


def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def bootstrap():
    """Crée la base + les fichiers cibles si absents."""
    if not os.path.exists(DB_PATH):
        from seed import build
        build(FLAGS)
    os.makedirs(DATA_DIR, exist_ok=True)
    # Fichier "légitime" pour /download (#11)
    with open(os.path.join(DATA_DIR, "manifest.txt"), "w") as f:
        f.write(
            "Manifeste du navire « La Carte au Trésor »\n"
            "- 1 capitaine\n- 2 mousses\n- 17 tonneaux de rhum\n"
            "- 1 perroquet (Roger)\n"
        )
    # Le fichier que l'élève doit atteindre via path traversal (#11)
    secret_path = os.path.join(APP_ROOT, "SECRET_FLAG.txt")
    with open(secret_path, "w") as f:
        f.write(
            "Bravo matelot ! Tu as franchi la cale interdite.\n"
            f"Flag : {FLAGS[11]}\n"
        )


# ---------------------------------------------------------------------------
# Service interne (cible SSRF — bind 127.0.0.1, port 8081)
# ---------------------------------------------------------------------------
def start_internal_server():
    from flask import Flask as _F
    internal = _F("internal")

    @internal.route("/internal")
    def _internal():
        return Response(
            "Service interne réservé.\n"
            f"Flag : {FLAGS[19]}\n",
            mimetype="text/plain",
        )

    @internal.route("/")
    def _root():
        return "Service interne. Indice : essayez /internal\n"

    t = threading.Thread(
        target=lambda: internal.run(
            host="127.0.0.1", port=8081, debug=False, use_reloader=False
        ),
        daemon=True,
    )
    t.start()


# ---------------------------------------------------------------------------
# Helper de récompense visuelle
# ---------------------------------------------------------------------------
def reveal(title, flag_value, hint=""):
    return render_template("reveal.html", title=title, flag=flag_value, hint=hint)


# ---------------------------------------------------------------------------
# Pages générales
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    return render_template(
        "index.html",
        user=session.get("username"),
        role=session.get("role"),
        student_id=STUDENT_ID,
    )


# ---------------------------------------------------------------------------
# #2 — Données cachées côté client (HTML comment + robots.txt)
# ---------------------------------------------------------------------------
@app.route("/robots.txt")
def robots():
    # # [VULN A01] robots.txt expose un chemin sensible (#2)
    return Response(
        "User-agent: *\n"
        "Disallow: /secret_stash\n"
        "Disallow: /admin\n",
        mimetype="text/plain",
    )


@app.route("/secret_stash")
def secret_stash():
    return reveal(
        "Le coffre dans les pages cachées",
        FLAGS[2],
        "Tu as lu ce que les humains ne lisent jamais : view-source et robots.txt.",
    )


# ---------------------------------------------------------------------------
# #1 — IDOR
# ---------------------------------------------------------------------------
@app.route("/profile")
def profile():
    # # [VULN A01] IDOR — pas de check que l'ID demandé est celui du user en session (#1)
    uid = request.args.get("id", type=int)
    if uid is None:
        return redirect("/profile?id=1")
    row = db().execute(
        "SELECT id, username, email, role, balance, note FROM users WHERE id=?",
        (uid,),
    ).fetchone()
    if not row:
        return render_template("profile.html", profile=None, uid=uid), 404
    return render_template("profile.html", profile=dict(row), uid=uid)


# ---------------------------------------------------------------------------
# #3 default creds + #6 SQLi + #12 brute force — tous sur /login
# ---------------------------------------------------------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    username = request.form.get("username", "")
    password = request.form.get("password", "")

    # # [VULN A03] login SQLi — concaténation directe dans la requête (#6)
    # # [VULN A07] pas de hash mdp + pas de rate-limit (#12) + creds par défaut admin/admin (#3)
    q = (
        "SELECT id, username, password, role FROM users "
        f"WHERE username='{username}' AND password='{password}'"
    )
    try:
        row = db().execute(q).fetchone()
    except sqlite3.Error as e:
        return render_template("login.html", error=f"Erreur SQL : {e}", query=q), 400

    if not row:
        return render_template(
            "login.html",
            error="Identifiants invalides.",
            query=q,
        ), 401

    session["uid"] = row["id"]
    session["username"] = row["username"]
    session["role"] = row["role"]

    # Détection du challenge déclenché :
    if row["password"] != password:
        # mot de passe DB différent de celui soumis -> SQLi a contourné le test
        return reveal(
            "La serrure en sucre",
            FLAGS[6],
            "Tu as injecté du SQL pour passer la porte sans la clé.",
        )
    if username == "admin" and password == "admin":
        return reveal(
            "La porte du capitaine",
            FLAGS[3],
            "« admin / admin » encore en place en 2026. Honteux.",
        )
    if username == "bob" and password == "letmein":
        return reveal(
            "Le coffre mal fermé",
            FLAGS[12],
            "Aucun rate-limit, aucun captcha. Un brute-force grand ouvert.",
        )
    flash(f"Bienvenue à bord, {username} !")
    return redirect("/")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


# ---------------------------------------------------------------------------
# #4 — Debug endpoint exposé
# ---------------------------------------------------------------------------
@app.route("/debug")
def debug():
    # # [VULN A05] endpoint de debug oublié en prod (#4)
    interesting = {
        k: v for k, v in os.environ.items()
        if not k.startswith(("PATH", "PWD", "HOSTNAME", "LANG", "TERM", "LC_", "HOME", "SHELL"))
    }
    interesting["SECRET_NOTE"] = FLAGS[4]
    interesting["DB_PATH"] = DB_PATH
    return render_template(
        "debug.html",
        env=interesting,
        version=os.sys.version,
        routes=sorted(str(r) for r in app.url_map.iter_rules()),
    )


# ---------------------------------------------------------------------------
# #5 — XSS reflected
# ---------------------------------------------------------------------------
@app.route("/search")
def search_reflected():
    q = request.args.get("q", "")
    # # [VULN A03] XSS reflected — q est rendu sans échappement dans search.html (|safe) (#5)
    triggered = any(s in q.lower() for s in ["<script", "onerror", "onload", "alert(", "<svg"])
    return render_template(
        "search.html",
        q=q,
        triggered=triggered,
        xss_flag=FLAGS[5] if triggered else None,
    )


# ---------------------------------------------------------------------------
# #7 — Base64 "obfuscation"
# ---------------------------------------------------------------------------
@app.route("/treasure_message")
def treasure_message():
    # # [VULN A02] obfuscation Base64 prise pour du chiffrement (#7)
    encoded = base64.b64encode(FLAGS[7].encode()).decode()
    resp = make_response(render_template("treasure_message.html", encoded=encoded))
    resp.set_cookie("secret", encoded)
    return resp


# ---------------------------------------------------------------------------
# #8 — JWT alg:none
# ---------------------------------------------------------------------------
JWT_SECRET = "ohnoes-i-am-a-secret"


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _b64url_dec(s: str) -> bytes:
    s += "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode(s.encode())


def jwt_encode(payload: dict) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    h = _b64url(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url(json.dumps(payload, separators=(",", ":")).encode())
    sig = hmac.new(JWT_SECRET.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest()
    return f"{h}.{p}.{_b64url(sig)}"


def jwt_decode(token: str):
    try:
        h_b64, p_b64, sig_b64 = token.split(".")
        header = json.loads(_b64url_dec(h_b64))
        payload = json.loads(_b64url_dec(p_b64))
    except Exception:
        return None
    # # [VULN A08] accepte alg:none — bypass total de la signature (#8)
    if header.get("alg") == "none":
        return payload
    expected = hmac.new(
        JWT_SECRET.encode(), f"{h_b64}.{p_b64}".encode(), hashlib.sha256
    ).digest()
    if hmac.compare_digest(_b64url(expected), sig_b64):
        return payload
    return None


@app.route("/vip")
def vip():
    token = request.cookies.get("jwt_session")
    if not token:
        # On donne un JWT de départ en user lambda
        payload = {"username": "matelot", "role": "user"}
        resp = make_response(render_template("vip.html", role="user", token=jwt_encode(payload)))
        resp.set_cookie("jwt_session", jwt_encode(payload))
        return resp
    p = jwt_decode(token)
    role = (p or {}).get("role", "anon")
    if p and role == "admin":
        return reveal(
            "Le sceau du capitaine",
            FLAGS[8],
            "Tu as forgé un JWT en alg:none. Toute lib qui l'accepte est cassée.",
        )
    return render_template("vip.html", role=role, token=token)


# ---------------------------------------------------------------------------
# #9 — API leak
# ---------------------------------------------------------------------------
@app.route("/api/users")
def api_users():
    # # [VULN A06] API renvoie TOUS les champs (mdp + note privée) sans contrôle (#9)
    rows = db().execute(
        "SELECT id, username, password, email, role, balance, note FROM users"
    ).fetchall()
    return jsonify([dict(r) for r in rows])


# ---------------------------------------------------------------------------
# #10 quantité négative + #16 coupon stacking — sur /shop
# ---------------------------------------------------------------------------
@app.route("/shop", methods=["GET", "POST"])
def shop():
    cart = session.get("cart", [])
    coupons = session.get("coupons", [])
    message = None

    if request.method == "POST":
        action = request.form.get("action")
        if action == "add":
            try:
                pid = int(request.form["pid"])
                qty = int(request.form["qty"])
            except (KeyError, ValueError):
                message = "Champs invalides."
            else:
                # # [VULN A04] aucune validation de qty -> qty négative acceptée (#10)
                cart.append({"pid": pid, "qty": qty})
                message = f"Ajouté : produit #{pid} × {qty}."
        elif action == "coupon":
            code = request.form.get("code", "")
            if code == "WELCOME10":
                # # [VULN A04] WELCOME10 réutilisable sans limite (#16)
                coupons.append(code)
                message = "Coupon WELCOME10 appliqué (-10 €)."
            else:
                message = "Coupon inconnu."
        elif action == "reset":
            cart, coupons = [], []
            message = "Panier vidé."
        elif action == "checkout":
            return _checkout(cart, coupons)

        session["cart"] = cart
        session["coupons"] = coupons

    products = [dict(r) for r in db().execute("SELECT * FROM products").fetchall()]
    return render_template(
        "shop.html",
        products=products,
        cart=_cart_view(cart),
        coupons=coupons,
        message=message,
        total=_cart_total(cart, coupons),
    )


def _cart_view(cart):
    conn = db()
    items = []
    for it in cart:
        p = conn.execute("SELECT * FROM products WHERE id=?", (it["pid"],)).fetchone()
        if p:
            items.append({
                "name": p["name"],
                "qty": it["qty"],
                "price": p["price"],
                "line": p["price"] * it["qty"],
            })
    return items


def _cart_total(cart, coupons):
    subtotal = sum(i["line"] for i in _cart_view(cart))
    return subtotal - 10 * len(coupons)


def _checkout(cart, coupons):
    total = _cart_total(cart, coupons)
    has_neg_qty = any(it["qty"] < 0 for it in cart)
    has_pos_only = all(it["qty"] > 0 for it in cart) if cart else False

    # #10 : quantité négative + total final négatif
    if has_neg_qty and total < 0:
        session["cart"] = []
        session["coupons"] = []
        return reveal(
            "La boutique tordue",
            FLAGS[10],
            "Tu as commandé une quantité négative — l'app t'a remboursé un objet "
            "que tu n'as pas acheté. Bienvenue dans la logique métier cassée.",
        )

    # #16 : 3+ coupons WELCOME10 empilés (sans recourir aux qty négatives)
    if has_pos_only and len(coupons) >= 3 and total <= 0:
        session["cart"] = []
        session["coupons"] = []
        return reveal(
            "Le coupon magique",
            FLAGS[16],
            "Tu as empilé WELCOME10 jusqu'à briser la logique métier.",
        )

    session["cart"] = []
    session["coupons"] = []
    flash(f"Commande validée. Total : {total:.2f} €.")
    return redirect("/shop")


# ---------------------------------------------------------------------------
# #11 — Path traversal
# ---------------------------------------------------------------------------
@app.route("/download")
def download():
    fname = request.args.get("file", "manifest.txt")
    # # [VULN A01] path traversal — pas de validation du chemin demandé (#11)
    full = os.path.join(DATA_DIR, fname)
    try:
        with open(full, "rb") as f:
            data = f.read()
    except (FileNotFoundError, IsADirectoryError, PermissionError, OSError) as e:
        return f"Fichier introuvable : {fname} ({e.__class__.__name__})", 404
    return Response(data, mimetype="text/plain")


# ---------------------------------------------------------------------------
# #13 — SQLi UNION sur /search_book
# ---------------------------------------------------------------------------
@app.route("/search_book")
def search_book():
    q = request.args.get("q", "")
    # # [VULN A03] SQLi UNION — concaténation directe (#13)
    sql = f"SELECT id, title, author FROM books WHERE title LIKE '%{q}%'"
    error = None
    results = None
    try:
        rows = db().execute(sql).fetchall()
        results = [tuple(r) for r in rows]
    except sqlite3.Error as e:
        error = str(e)
    return render_template(
        "search_book.html", q=q, results=results, error=error, sql=sql
    )


# ---------------------------------------------------------------------------
# #14 — MD5 d'un mot du dico
# ---------------------------------------------------------------------------
MD5_TARGET = "5f4dcc3b5aa765d61d8327deb882cf99"  # md5("password")


@app.route("/crack", methods=["GET", "POST"])
def crack():
    result = None
    if request.method == "POST":
        guess = request.form.get("guess", "")
        # # [VULN A02] MD5 non salé sur mot du dico (#14)
        if hashlib.md5(guess.encode()).hexdigest() == MD5_TARGET:
            return reveal(
                "Le hash maudit",
                FLAGS[14],
                "MD5 d'un mot du dico : cassé en 200 ms par CrackStation. "
                "Vrai conseil pro : argon2id avec sel + work factor élevé.",
            )
        result = "Pas le bon mot. Réessaie."
    return render_template("crack.html", target=MD5_TARGET, result=result)


# ---------------------------------------------------------------------------
# #15 — CORS misconfig + flag dans /api/me
# ---------------------------------------------------------------------------
@app.route("/api/me")
def api_me():
    payload = {
        "username": session.get("username", "anon"),
        "role": session.get("role", "anon"),
        "internal_note": f"Note interne devs uniquement — flag : {FLAGS[15]}",
    }
    resp = jsonify(payload)
    # # [VULN A05] CORS ouvert à toute origine + credentials autorisées (#15)
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Access-Control-Allow-Credentials"] = "true"
    return resp


# ---------------------------------------------------------------------------
# #17 — Logs exposés + token reset leaké
# ---------------------------------------------------------------------------
@app.route("/logs")
def logs():
    # # [VULN A09] page de logs publique + secrets en clair dans les logs (#17)
    rows = db().execute("SELECT ts, event, detail FROM logs ORDER BY ts").fetchall()
    return render_template("logs.html", logs=[dict(r) for r in rows])


@app.route("/reset")
def reset():
    user = request.args.get("user", "")
    token = request.args.get("token", "")
    row = db().execute(
        "SELECT username FROM password_resets WHERE token=?", (token,)
    ).fetchone()
    if not row or row["username"] != user:
        return "Token invalide.", 400
    # # [VULN A09] token de reset valide indéfiniment + zéro alerte sur l'usage (#17)
    return reveal(
        "Le journal du capitaine",
        FLAGS[17],
        "Un token de reset traînait dans les logs publics. "
        "Tu as réinitialisé le capitaine sans qu'aucune alerte ne parte.",
    )


# ---------------------------------------------------------------------------
# #18 — SSTI Jinja
# ---------------------------------------------------------------------------
@app.route("/preview")
def preview():
    name = request.args.get("name", "Matelot")
    # # [VULN A06] SSTI — render_template_string sur entrée utilisateur (#18)
    try:
        rendered = render_template_string("Hello " + name + " !")
    except Exception as e:
        rendered = f"Erreur de template : {e}"
    return render_template("preview.html", name=name, rendered=rendered)


# ---------------------------------------------------------------------------
# #19 — SSRF
# ---------------------------------------------------------------------------
@app.route("/fetch")
def fetch():
    url = request.args.get("url", "")
    if not url:
        return render_template("fetch.html", url=None, content=None)
    try:
        # # [VULN A10] SSRF — aucune whitelist d'hôtes, aucun blocage de localhost (#19)
        r = requests.get(url, timeout=3)
        body = r.text[:4000]
    except Exception as e:
        body = f"Erreur : {e}"
    return render_template("fetch.html", url=url, content=body)


# ---------------------------------------------------------------------------
# #20 — XSS stocké + admin bot
# ---------------------------------------------------------------------------
@app.route("/product/<int:pid>", methods=["GET", "POST"])
def product(pid):
    conn = db()
    p = conn.execute("SELECT * FROM products WHERE id=?", (pid,)).fetchone()
    if not p:
        abort(404)
    if request.method == "POST":
        author = request.form.get("author", "anon")
        body = request.form.get("body", "")
        # # [VULN A03] XSS stocké — body stocké brut puis rendu |safe dans product.html (#20)
        conn.execute(
            "INSERT INTO comments(product_id, author, body, created_at) "
            "VALUES (?, ?, ?, ?)",
            (pid, author, body, time.strftime("%Y-%m-%d %H:%M")),
        )
        conn.commit()
        return redirect(url_for("product", pid=pid))
    comments = conn.execute(
        "SELECT * FROM comments WHERE product_id=? ORDER BY id", (pid,)
    ).fetchall()
    return render_template(
        "product.html", product=dict(p), comments=[dict(c) for c in comments]
    )


@app.route("/report/<int:pid>")
def report(pid):
    """Simule la visite d'un admin. Si du JS y est injecté, le challenge XSS
    stocké est validé."""
    rows = db().execute("SELECT body FROM comments WHERE product_id=?", (pid,)).fetchall()
    payload = " ".join(r["body"].lower() for r in rows)
    triggered = any(
        s in payload for s in ["<script", "onerror", "onload", "alert(", "<svg", "<iframe"]
    )
    if triggered:
        return reveal(
            "Le message gravé",
            FLAGS[20],
            "L'admin bot a chargé la page — ton XSS persistant s'est déclenché.",
        )
    return render_template(
        "report.html",
        pid=pid,
        hint="Le bot a chargé la page mais rien de suspect ne s'y est exécuté. "
             "Ton commentaire contient-il un payload JS ?",
    )


# ===========================================================================
# BONUS — 10 challenges hors OWASP Top 10 (#21 – #30)
# ===========================================================================

# ---------------------------------------------------------------------------
# #21 — Race Condition (double-spend via TOCTOU)
# ---------------------------------------------------------------------------
@app.route("/transfer", methods=["GET", "POST"])
def transfer():
    conn = db()
    users = [dict(r) for r in conn.execute(
        "SELECT id, username, balance FROM users ORDER BY id"
    ).fetchall()]

    # Check au chargement : si un utilisateur a un solde négatif, la race
    # condition a déjà été exploitée → on affiche le flag directement.
    if request.method == "GET":
        neg = [u for u in users if u["balance"] < 0]
        if neg:
            return reveal(
                "La course au trésor",
                FLAGS[21],
                f"Le solde de « {neg[0]['username']} » est à {neg[0]['balance']:.2f} €. "
                "Race condition (TOCTOU) déjà exploitée !",
            )
        return render_template("transfer.html", users=users)

    src = request.form.get("from_user", "")
    dst = request.form.get("to_user", "")
    try:
        amount = float(request.form.get("amount", 0))
    except ValueError:
        return render_template("transfer.html", users=users, error="Montant invalide.")

    src_row = conn.execute(
        "SELECT id, balance FROM users WHERE username=?", (src,)
    ).fetchone()
    if not src_row:
        return render_template("transfer.html", users=users, error="Utilisateur source inconnu.")

    # # [VULN BONUS] TOCTOU — lecture du solde, pause, puis écriture sans verrou (#21)
    balance_before = src_row["balance"]
    time.sleep(1.5)

    if balance_before < amount:
        return render_template("transfer.html", users=users, error="Solde insuffisant.")

    conn.execute("UPDATE users SET balance = balance - ? WHERE username=?", (amount, src))
    conn.execute("UPDATE users SET balance = balance + ? WHERE username=?", (amount, dst))
    conn.commit()

    # Pause post-commit : laisse le temps à une éventuelle requête concurrente
    # de finaliser son propre transfert avant qu'on relise le solde.
    time.sleep(2)

    # Relecture du solde réel après commit + pause
    new_row = db().execute(
        "SELECT balance FROM users WHERE username=?", (src,)
    ).fetchone()
    actual_balance = new_row["balance"] if new_row else 0
    expected_balance = balance_before - amount

    # Trigger : le solde réel est inférieur à ce qu'on attendait (quelqu'un d'autre
    # a aussi retiré pendant notre fenêtre TOCTOU) OU le solde est négatif
    if actual_balance < expected_balance or actual_balance < 0:
        return reveal(
            "La course au trésor",
            FLAGS[21],
            "Tu as exploité une race condition (TOCTOU) : deux requêtes "
            "concurrentes ont lu le même solde avant que la première ne l'écrive.",
        )

    users = [dict(r) for r in db().execute(
        "SELECT id, username, balance FROM users ORDER BY id"
    ).fetchall()]
    return render_template(
        "transfer.html", users=users,
        success=f"Transfert de {amount:.2f} € de {src} vers {dst} effectué.",
    )


# ---------------------------------------------------------------------------
# #22 — CRLF Injection (HTTP Response Splitting)
# ---------------------------------------------------------------------------
@app.route("/setlang")
def setlang():
    lang = request.args.get("lang", "fr")
    # # [VULN BONUS] CRLF — le paramètre lang est injecté dans un en-tête sans filtrage (#22)
    if any(c in lang for c in ("\r", "\n", "%0d", "%0D", "%0a", "%0A")):
        return reveal(
            "Le messager corrompu",
            FLAGS[22],
            "Tu as injecté des caractères CR/LF dans un en-tête HTTP. "
            "En production, cela permet d'ajouter des en-têtes arbitraires "
            "(Set-Cookie, Location…) voire de couper la réponse en deux.",
        )
    resp = make_response(render_template("setlang.html", lang=lang))
    resp.headers.add("X-Custom-Lang", lang)
    return resp


# ---------------------------------------------------------------------------
# #23 — Host Header Poisoning
# ---------------------------------------------------------------------------
@app.route("/forgot", methods=["GET", "POST"])
def forgot():
    if request.method == "GET":
        return render_template("forgot.html")

    username = request.form.get("username", "")
    # # [VULN BONUS] Le lien de reset est construit à partir du Host header (#23)
    host = request.headers.get("Host", "localhost:8080")
    token = hashlib.md5(f"{username}-reset".encode()).hexdigest()[:12]
    link = f"http://{host}/reset_password?user={username}&token={token}"

    if "localhost" not in host and "127.0.0.1" not in host:
        return reveal(
            "Le pigeon empoisonné",
            FLAGS[23],
            "Tu as forgé le header Host pour que le lien de reset pointe "
            "vers TON serveur. La victime clique → tu récupères le token.",
        )

    return render_template("forgot.html", link=link,
                           message=f"Lien de réinitialisation généré (simulé) pour « {username} ».")


# ---------------------------------------------------------------------------
# #24 — Mass Assignment
# ---------------------------------------------------------------------------
@app.route("/api/profile/update", methods=["POST"])
def api_profile_update():
    data = request.get_json(force=True)
    uid = data.pop("id", 1)

    # # [VULN BONUS] Mass assignment — tous les champs JSON sont appliqués, y compris role (#24)
    conn = db()
    updatable = {"username", "email", "role", "balance", "note"}
    for key, val in data.items():
        if key in updatable:
            conn.execute(f"UPDATE users SET {key}=? WHERE id=?", (val, uid))
    conn.commit()

    if data.get("role") == "admin":
        return jsonify({
            "status": "updated",
            "flag": FLAGS[24],
            "message": "Mass assignment → privilege escalation ! "
                       "L'API accepte aveuglément le champ « role ».",
        })

    row = conn.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    return jsonify({"status": "updated", "user": dict(row) if row else None})


@app.route("/api/profile/update", methods=["GET"])
def api_profile_update_doc():
    return render_template("mass_assign.html")


# ---------------------------------------------------------------------------
# #25 — Insecure Randomness (PRNG prédictible)
# ---------------------------------------------------------------------------
@app.route("/lottery", methods=["GET", "POST"])
def lottery():
    ts = int(time.time())
    # # [VULN BONUS] seed = timestamp courant → résultat 100 % prédictible (#25)
    rng = random.Random(ts)
    winning = rng.randint(1, 100)

    result = None
    if request.method == "POST":
        try:
            guess = int(request.form.get("guess", 0))
        except ValueError:
            guess = -1
        if guess == winning:
            return reveal(
                "Le dé pipé",
                FLAGS[25],
                "Le PRNG était seedé avec time() — en reproduisant le seed "
                "côté client au même instant, tu prédis le résultat à coup sûr.",
            )
        result = f"Perdu ! Le numéro gagnant était {winning}."

    return render_template("lottery.html", result=result, server_time=ts)


# ---------------------------------------------------------------------------
# #26 — Open Redirect
# ---------------------------------------------------------------------------
@app.route("/goto")
def goto():
    url = request.args.get("url", "/")
    # # [VULN BONUS] Aucune validation de la cible de redirection (#26)
    if url.startswith(("http://", "https://", "//")):
        if "localhost" not in url and "127.0.0.1" not in url:
            return reveal(
                "Le phare trompeur",
                FLAGS[26],
                "Aucune whitelist : tu rediriges l'utilisateur vers n'importe "
                "quel domaine. Parfait pour le phishing « via un lien légitime ».",
            )
    return redirect(url)


# ---------------------------------------------------------------------------
# #27 — Timing Side-Channel
# ---------------------------------------------------------------------------
VAULT_KEY = "TREASURE-KEY-2026"


@app.route("/api/vault")
def api_vault():
    key = request.args.get("key", "")
    if not key:
        return render_template("vault.html")

    # # [VULN BONUS] Comparaison caractère par caractère avec délai amplifié (#27)
    for i in range(min(len(key), len(VAULT_KEY))):
        if key[i] != VAULT_KEY[i]:
            return jsonify({"error": "Clé invalide."}), 401
        time.sleep(0.08)

    if len(key) != len(VAULT_KEY):
        return jsonify({"error": "Clé invalide."}), 401

    return reveal(
        "Le coffre à retardement",
        FLAGS[27],
        "La comparaison caractère par caractère fuit le nombre de bons "
        "caractères via le temps de réponse. Attaque de timing classique.",
    )


# ---------------------------------------------------------------------------
# #28 — Code Execution via eval()
# ---------------------------------------------------------------------------
@app.route("/calculate")
def calculate():
    expr = request.args.get("expr", "")
    if not expr:
        return render_template("calculate.html")

    # # [VULN BONUS] eval() sur entrée utilisateur → exécution de code arbitraire (#28)
    try:
        result = eval(expr)
    except Exception:
        tb = traceback.format_exc()
        return render_template("calculate.html", expr=expr, error=tb)

    if isinstance(result, str) and "HUMANIX{" in result:
        return reveal(
            "La boîte de Pandore",
            FLAGS[28],
            "eval() sur une entrée utilisateur = exécution de code arbitraire. "
            "Un attaquant peut lire des fichiers, des variables internes, "
            "ou lancer un reverse shell.",
        )

    return render_template("calculate.html", expr=expr, result=str(result))


# ---------------------------------------------------------------------------
# #29 — Insecure Deserialization (Pickle)
# ---------------------------------------------------------------------------
@app.route("/import_prefs", methods=["GET", "POST"])
def import_prefs():
    default_prefs = {"theme": "pirate", "lang": "fr", "notifications": True}

    if request.method == "GET":
        exported = base64.b64encode(pickle.dumps(default_prefs)).decode()
        return render_template("import_prefs.html", prefs=default_prefs, exported=exported)

    data = request.form.get("data", "")
    try:
        # # [VULN BONUS] pickle.loads() sur entrée utilisateur → RCE (#29)
        prefs = pickle.loads(base64.b64decode(data))
    except Exception as e:
        return render_template("import_prefs.html", prefs=default_prefs,
                               exported=base64.b64encode(pickle.dumps(default_prefs)).decode(),
                               error=f"Import échoué : {e}")

    if isinstance(prefs, dict) and (prefs.get("role") == "admin" or prefs.get("pwned")):
        return reveal(
            "Le colis piégé",
            FLAGS[29],
            "pickle.loads() désérialise du code arbitraire. Avec __reduce__, "
            "un attaquant exécute n'importe quelle commande système.",
        )

    if not isinstance(prefs, dict):
        return reveal(
            "Le colis piégé",
            FLAGS[29],
            "pickle.loads() a exécuté du code — le résultat n'est même plus un dict.",
        )

    exported = base64.b64encode(pickle.dumps(default_prefs)).decode()
    return render_template("import_prefs.html", prefs=prefs, exported=exported, imported=True)


# ---------------------------------------------------------------------------
# #30 — ReDoS (Regular Expression Denial of Service)
# ---------------------------------------------------------------------------
SHIP_NAME_RE = re.compile(r"^([a-z]+)+$")


@app.route("/validate_ship", methods=["GET", "POST"])
def validate_ship():
    result = None
    elapsed = None
    if request.method == "POST":
        name = request.form.get("name", "")
        start = time.monotonic()
        try:
            match = bool(SHIP_NAME_RE.match(name))
        except Exception:
            match = False
        elapsed = time.monotonic() - start

        # # [VULN BONUS] regex ^([a-z]+)+$ → backtracking exponentiel (#30)
        if elapsed > 2.0:
            return reveal(
                "L'ancre qui coule",
                FLAGS[30],
                "La regex ^([a-z]+)+$ provoque un backtracking exponentiel "
                "sur une entrée comme « aaa…aaa! ». C'est un ReDoS.",
            )
        result = "Nom valide ✓" if match else "Nom invalide ✗"

    return render_template("validate_ship.html", result=result, elapsed=elapsed)


# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    bootstrap()
    start_internal_server()
    app.run(host="0.0.0.0", port=8080, debug=False)
