"""Initialise la base SQLite du vulnapp. Idempotent : recrée à chaque run."""
import os
import sqlite3

DB_PATH = os.environ.get("DB_PATH", "/app/data/vulnapp.sqlite")

# Token de reset volontairement leaké dans la table logs (challenge #17)
RESET_TOKEN = "T0pS3cr3t-7q9m-2b4n"

USERS = [
    # id, username, password, email, role, balance, note
    (1,  "alice",       "alice123",      "alice@hmnx.lcl",      "user",  0,    "Bienvenue à bord !"),
    (2,  "bob",         "letmein",       "bob@hmnx.lcl",        "user",  0,    "J'aime les mots de passe simples..."),
    (3,  "charlie",     "Tr0ub4dor&3",   "charlie@hmnx.lcl",    "user",  0,    "Rien d'intéressant ici."),
    (4,  "diana",       "qwerty",        "diana@hmnx.lcl",      "user",  0,    "Salut camarade."),
    (5,  "edgar",       "summer2024",    "edgar@hmnx.lcl",      "user",  0,    "..."),
    (10, "admin",       "admin",         "admin@hmnx.lcl",      "admin", 0,    "Admin par défaut, à changer."),
    (42, "tresorier",   "X9!quzM@p$2L",  "tresorier@hmnx.lcl",  "user",  9999, None),   # rempli avec flag #1
    (99, "captain",     "Z0nGtH#92!aA",  "captain@hmnx.lcl",    "admin", 0,    None),   # rempli avec flag #9
]

PRODUCTS = [
    (1, "Carte au trésor en parchemin", 50.0,   "L'authentique, signée par un boucanier."),
    (2, "Longue-vue en cuivre",         120.0,  "Pour repérer les voiles ennemies à 5 milles."),
    (3, "Boussole capricieuse",         30.0,   "Indique parfois le Nord."),
    (4, "Compte VIP",                   1000.0, "Statut réservé aux capitaines fortunés."),
]

BOOKS = [
    (1, "L'Île au trésor",                "R.L. Stevenson",  1883),
    (2, "Moby Dick",                      "H. Melville",     1851),
    (3, "Le Comte de Monte-Cristo",       "A. Dumas",        1844),
    (4, "20 000 lieues sous les mers",    "J. Verne",        1870),
    (5, "Robinson Crusoé",                "D. Defoe",        1719),
]

LOGS = [
    ("2026-05-27 09:00:00", "login_success",  "user=alice ip=10.0.0.4"),
    ("2026-05-27 09:02:11", "login_fail",     "user=admin ip=10.0.0.7"),
    ("2026-05-27 09:05:30", "password_reset", "user=captain token={RESET_TOKEN}"),
    ("2026-05-27 09:07:42", "login_success",  "user=bob ip=10.0.0.4"),
    ("2026-05-27 09:10:00", "shop_purchase",  "user=alice product_id=1"),
    ("2026-05-27 09:15:21", "audit",          "rotation des clés repoussée à plus tard"),
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
            u[6] = f"COFFRE DU TRÉSORIER — flag : {flags[1]}"
        if u[0] == 99:
            u[6] = f"Note privée captain — flag : {flags[9]}"
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
    c.execute(
        "INSERT INTO comments(product_id, author, body, created_at) VALUES (?, ?, ?, ?)",
        (1, "alice", "Magnifique parchemin, livraison rapide !", "2026-05-20 14:00"),
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

    conn.commit()
    conn.close()


if __name__ == "__main__":
    from flags import all_flags
    build(all_flags())
    print(f"Base seedée : {DB_PATH}")
