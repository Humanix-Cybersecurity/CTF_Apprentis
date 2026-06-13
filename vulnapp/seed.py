"""Initialise la base SQLite du vulnapp. Idempotent : recrée à chaque run."""
import os
import sqlite3

DB_PATH = os.environ.get("DB_PATH", "/app/data/vulnapp.sqlite")

# Token de reset volontairement leaké dans la table logs (challenge #17)
RESET_TOKEN = "T0pS3cr3t-7q9m-2b4n"

USERS = [
    # id, username, password, email, role, balance, note
    (1,  "alice",     "alice123",    "alice@hmnx.lcl",     "user",  0,
     "Vigie de quart depuis 3 ans. Toujours la première à bord, avant même l'aube. "
     "Dernière note : « J'ai vu de la lumière dans la cabine du trésorier à 3h du matin. "
     "Ce n'est pas normal. Je n'en parlerai à personne. »"),

    (2,  "bob",       "letmein",     "bob@hmnx.lcl",       "user",  0,
     "Matelot de pont. Mot de passe écrit sur un bout de papier collé sous sa couchette. "
     "Dernière note : « J'oublie toujours mes mots de passe alors je prends un truc simple. "
     "De toute façon, qui irait pirater un pirate ? »"),

    (3,  "charlie",   "Tr0ub4dor&3", "charlie@hmnx.lcl",   "user",  0,
     "Quartier-maître. Rien d'intéressant ici. Absolument rien. Ne cherchez pas. "
     "D'ailleurs il n'y a aucune raison de consulter les logs du 27 mai."),

    (4,  "diana",     "qwerty",      "diana@hmnx.lcl",     "user",  0,
     "Navigatrice en chef. A les accès à tous les systèmes du navire pour « raisons de navigation ». "
     "Dernière note : « Le capitaine m'a donné le code du coffre-fort avant de partir. "
     "En cas de besoin, dit-il. Quel besoin ? »"),

    (5,  "edgar",     "summer2024",  "edgar@hmnx.lcl",     "user",  0,
     "..."),

    (10, "admin",     "admin",       "admin@hmnx.lcl",     "admin", 0,
     "Le Second du navire. Chargé de la sécurité des systèmes. "
     "TODO : changer le mot de passe par défaut. TODO : activer le rate-limit. "
     "TODO : désactiver /debug en production. (note datée du 12 janvier 2025)"),

    (42, "tresorier", "X9!quzM@p$2L", "tresorier@hmnx.lcl", "user", 9999, None),
    (99, "captain",   "Z0nGtH#92!aA", "captain@hmnx.lcl",  "admin", 0,    None),
]

PRODUCTS = [
    (1, "Carte au trésor en parchemin", 50.0,
     "L'authentique carte du capitaine, signée de sa main. Des annotations récentes "
     "ont été grattées — quelqu'un a essayé d'effacer des coordonnées. "
     "Pourquoi vouloir cacher la destination ?"),

    (2, "Longue-vue en cuivre", 120.0,
     "Pour repérer les voiles ennemies à 5 milles. Celle-ci appartenait au capitaine. "
     "Alice l'a retrouvée sur le pont le matin du 27 mai, abandonnée. "
     "Le capitaine ne s'en séparait jamais."),

    (3, "Boussole capricieuse", 30.0,
     "Indique parfois le Nord. Objet préféré de Diana, la navigatrice. "
     "Curiosité : l'aiguille pointe vers l'Isle de la Tortue depuis le 27 mai. "
     "Coïncidence ou signal ?"),

    (4, "Compte VIP", 1000.0,
     "Statut réservé aux capitaines fortunés. Depuis la disparition, "
     "seul le trésorier a les fonds pour se l'offrir. 9 999 doublons dans son compte — "
     "d'où vient cet argent ?"),
]

BOOKS = [
    (1,  "L'Île au trésor",                   "R.L. Stevenson",       1883),
    (2,  "Moby Dick",                          "H. Melville",          1851),
    (3,  "Le Comte de Monte-Cristo",           "A. Dumas",             1844),
    (4,  "20 000 lieues sous les mers",        "J. Verne",             1870),
    (5,  "Robinson Crusoé",                    "D. Defoe",             1719),
    (6,  "Les Mutinés de la Bounty",           "J. Nordhoff",          1932),
    (7,  "Journal du capitaine — Mai 2026",    "Capitaine",            2026),
    (8,  "Traité de navigation secrète",       "D. la Navigatrice",    2025),
    (9,  "Registre des comptes — confidentiel", "Le Trésorier",        2026),
    (10, "Carnet d'Edgar (pages arrachées)",   "Edgar",                2026),
]

LOGS = [
    ("2026-05-27 04:58:00", "login_success",   "user=alice ip=10.0.0.4 — connexion depuis le poste de vigie"),
    ("2026-05-27 05:02:00", "system_note",     "alice : « Lumière inhabituelle dans la cale. RAS officiel. »"),
    ("2026-05-27 06:30:00", "login_success",   "user=bob ip=10.0.0.5 — tentative 1/1 (mot de passe correct du premier coup pour une fois)"),

    ("2026-05-27 07:00:00", "login_fail",      "user=admin ip=10.0.0.7 — échec avec mot de passe 'admin123'"),
    ("2026-05-27 07:00:03", "login_success",   "user=admin ip=10.0.0.7 — connexion avec mot de passe par défaut admin/admin"),
    ("2026-05-27 07:01:00", "config_change",   "user=admin action=disable_audit_log reason='performances'"),

    ("2026-05-27 07:15:00", "password_reset",  "user=captain token={RESET_TOKEN} — demande de réinitialisation depuis ip=10.0.0.7"),
    ("2026-05-27 07:15:01", "system_warning",  "ALERTE : réinitialisation du compte capitaine depuis l'IP du Second"),

    ("2026-05-27 07:30:00", "transfer",        "user=tresorier from=coffre_principal to=isle_tortue_42 amount=3000 — « provisions »"),
    ("2026-05-27 07:31:00", "audit_bypass",    "user=charlie action=validate_transfer ref=isle_tortue_42 — validation sans double signature"),

    ("2026-05-27 08:00:00", "log_deletion",    "user=charlie action=purge_logs range=2026-05-24..2026-05-26 reason='rotation planifiée'"),
    ("2026-05-27 08:00:01", "system_note",     "ANOMALIE : rotation de logs non planifiée déclenchée manuellement"),

    ("2026-05-27 08:30:00", "access_grant",    "user=diana resource=navigation_charts,coffre_fort,communications — accès total accordé par admin"),
    ("2026-05-27 08:31:00", "file_access",     "user=diana file=/capitaine/journal_prive.txt — lecture sans autorisation"),

    ("2026-05-27 08:45:00", "login_success",   "user=edgar ip=10.0.0.8 — connexion silencieuse, aucune action enregistrée pendant 47 minutes"),
    ("2026-05-27 09:32:00", "logout",          "user=edgar — déconnexion. Note système : edgar n'a touché à rien. Ou bien les logs ont été effacés."),

    ("2026-05-27 09:00:00", "login_success",   "user=captain ip=10.0.0.1 — dernière connexion du capitaine"),
    ("2026-05-27 09:05:00", "message_sent",    "user=captain to=equipage subject='Message urgent' — message chiffré, contenu non lisible dans les logs"),
    ("2026-05-27 09:07:00", "system_alert",    "ALERTE CRITIQUE : porte de la cabine du capitaine — capteur d'ouverture déclenché"),
    ("2026-05-27 09:07:30", "system_alert",    "Capteur de coque — canot de sauvetage #3 largué"),
    ("2026-05-27 09:08:00", "system_note",     "Silence radio. Le capitaine ne répond plus."),

    ("2026-05-27 09:15:00", "audit",           "user=admin action=postpone_key_rotation reason='le capitaine n'est pas là pour valider'"),
    ("2026-05-27 09:20:00", "config_change",   "user=admin action=disable_alerts reason='trop de faux positifs'"),
    ("2026-05-27 10:00:00", "announcement",    "user=admin to=equipage message='Le capitaine est parti en mission secrète. Je prends le commandement.'"),
    ("2026-05-27 10:30:00", "transfer",        "user=tresorier from=coffre_principal to=fonds_equipage amount=500 — « prime de silence »"),
]

SEED_COMMENTS = [
    (1, "alice",     "Magnifique parchemin. J'ai remarqué des annotations grattées — "
                     "quelqu'un a modifié la carte récemment.", "2026-05-20 14:00"),
    (1, "bob",       "Trop cher pour moi. Le trésorier pourrait se l'offrir facilement vu "
                     "son solde...", "2026-05-21 09:30"),
    (2, "diana",     "Cette longue-vue est celle du capitaine. Qui l'a mise en vente ?", "2026-05-28 08:00"),
    (2, "edgar",     "...", "2026-05-28 08:15"),
    (3, "alice",     "La boussole pointe vers l'Isle de la Tortue. C'est là que "
                     "le trésorier a ses « contacts ».", "2026-05-28 10:00"),
    (4, "charlie",   "Rien à voir ici. Ce produit est parfaitement normal. "
                     "Arrêtez de poser des questions.", "2026-05-27 12:00"),
    (4, "tresorier", "Je prends le Compte VIP. Mettez-le sur mon compte.", "2026-05-27 14:00"),
]


def build(flags: dict) -> None:
    """flags : dict[int -> flag string] (cf. flags.all_flags())."""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # --- users -----------------------------------------------------------
    c.execute("""CREATE TABLE users (
        id INTEGER PRIMARY KEY,
        username TEXT UNIQUE,
        password TEXT,
        email TEXT,
        role TEXT,
        balance REAL,
        note TEXT
    )""")
    for row in USERS:
        u = list(row)
        if u[0] == 42:
            u[6] = (
                "COFFRE DU TRÉSORIER — Mouvements suspects : 3 transferts de 3 000 doublons "
                "vers un compte offshore « isle_tortue_42 » les 24, 25 et 26 mai 2026. "
                f"Qui a autorisé ces virements ? — flag : {flags[1]}"
            )
        if u[0] == 99:
            u[6] = (
                "MESSAGE PRIVÉ DU CAPITAINE — « Si vous lisez ceci, c'est que je ne suis "
                "plus là. La mutinerie a commencé quand j'ai découvert les détournements. "
                "Trois membres de l'équipage sont impliqués. Le trésorier blanchit l'or. "
                "Le quartier-maître couvre les traces. Et le troisième... je ne peux pas "
                f"encore le nommer. Cherchez dans les logs. » — flag : {flags[9]}"
            )
        c.execute("INSERT INTO users VALUES (?, ?, ?, ?, ?, ?, ?)", u)

    # --- products --------------------------------------------------------
    c.execute("""CREATE TABLE products (
        id INTEGER PRIMARY KEY, name TEXT, price REAL, description TEXT
    )""")
    c.executemany("INSERT INTO products VALUES (?, ?, ?, ?)", PRODUCTS)

    # --- books (challenge SQLi UNION) ------------------------------------
    c.execute("""CREATE TABLE books (
        id INTEGER PRIMARY KEY, title TEXT, author TEXT, year INTEGER
    )""")
    c.executemany("INSERT INTO books VALUES (?, ?, ?, ?)", BOOKS)

    # --- secrets (cible UNION) -------------------------------------------
    c.execute("""CREATE TABLE secrets (
        id INTEGER PRIMARY KEY, flag TEXT, description TEXT
    )""")
    c.execute("INSERT INTO secrets VALUES (?, ?, ?)",
              (1, flags[13], "secrets.flag — cible challenge SQLi UNION"))

    # --- comments (cible XSS stocké) -------------------------------------
    c.execute("""CREATE TABLE comments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        product_id INTEGER, author TEXT, body TEXT, created_at TEXT
    )""")
    for pid, author, body, created_at in SEED_COMMENTS:
        c.execute(
            "INSERT INTO comments(product_id, author, body, created_at) VALUES (?, ?, ?, ?)",
            (pid, author, body, created_at),
        )

    # --- logs (challenge A09) --------------------------------------------
    c.execute("""CREATE TABLE logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT, event TEXT, detail TEXT
    )""")
    for ts, ev, det in LOGS:
        det = det.replace("{RESET_TOKEN}", RESET_TOKEN)
        c.execute("INSERT INTO logs(ts, event, detail) VALUES (?, ?, ?)", (ts, ev, det))

    # --- password_resets (cible challenge #17) ---------------------------
    c.execute("""CREATE TABLE password_resets (
        token TEXT PRIMARY KEY, username TEXT, used INTEGER DEFAULT 0
    )""")
    c.execute("INSERT INTO password_resets VALUES (?, ?, 0)", (RESET_TOKEN, "captain"))

    # --- solved (tracking progression journal de bord) -------------------
    c.execute("""CREATE TABLE solved (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        challenge_id INTEGER UNIQUE,
        solved_at TEXT
    )""")

    conn.commit()
    conn.close()


if __name__ == "__main__":
    from flags import all_flags
    build(all_flags())
    print(f"Base seedée : {DB_PATH}")
