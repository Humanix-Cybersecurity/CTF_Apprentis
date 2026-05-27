# 🗺️ CTF « La Carte au Trésor »

CTF pédagogique d'initiation à la sécurité offensive — **OWASP Top 10 2021**,
20 challenges, public junior (~8 h de cours), par
[Humanix Cybersecurity](https://github.com/Humanix-Cybersecurity).

---

## ⚖️ Cadre légal — à lire AVANT toute manipulation

Ce CTF est un **environnement d'apprentissage avec consentement explicite** :
la vulnapp tourne sur **ta propre machine** (localhost), et le CTFd accepte
explicitement tes soumissions.

**Tout ce qui est appris ici ne se reproduit JAMAIS** sur un système dont
tu n'es pas propriétaire ou pour lequel tu n'as pas d'autorisation écrite.

- **Article 323-1 du Code pénal** (FR) : accès ou maintien frauduleux dans un
  STAD → **3 ans d'emprisonnement et 100 000 € d'amende**.
- **Article 323-2** : entrave ou altération d'un STAD → **5 ans, 150 000 €**.
- **Article 323-3** : introduction / suppression / modification frauduleuse
  de données → **5 ans, 150 000 €**.

> **Règle d'or** : *« On ne teste JAMAIS la sécurité d'un système sans
> autorisation écrite préalable de son propriétaire. »*

Hors d'un cadre légal (CTF de consentement, bug bounty avec scope, pentest
sous mandat) → **abstiens-toi**.

---

## 🎯 Comment ça marche

Le CTF a **deux briques indépendantes** :

| Brique | Où ? | Qui la lance ? |
|---|---|---|
| **Vulnapp** (ce repo) — l'appli à attaquer | sur **ta machine**, `http://localhost:8080` | **toi**, en local, via Docker |
| **CTFd** — la plateforme de scoring | URL publique communiquée par ton prof | **le prof** (hébergé par Humanix) |

Tu résous les challenges en local sur ta vulnapp, tu lis le flag, tu vas le
recopier dans le CTFd → ton score apparaît dans le classement.

---

## 🚀 Démarrage (1 commande)

Prérequis : **Docker** et **Docker Compose** (inclus avec Docker Desktop).

```bash
git clone https://github.com/Humanix-Cybersecurity/CTF_Apprentis.git
cd CTF_Apprentis/vulnapp
docker compose up --build
```

Puis ouvre <http://localhost:8080>. Bonne chasse, matelot 🏴‍☠️

Détails (mode anti-triche, dépannage, astuces F12) :
[`vulnapp/README.md`](vulnapp/README.md).

---

## 📦 Contenu du repo

```
CTF_Apprentis/
├── README.md             ← tu es ici
└── vulnapp/              ← l'application vulnérable (à lancer en local)
    ├── README.md         ← guide élève
    ├── Dockerfile
    ├── docker-compose.yml
    ├── requirements.txt
    ├── app.py            ← Flask, chaque vuln annotée `# [VULN A0X]`
    ├── flags.py          ← mode statique + dérivation HMAC(STUDENT_ID)
    ├── seed.py           ← init SQLite
    ├── static/style.css
    └── templates/        ← Jinja templates, thème dark CTF
```

> Le déploiement **CTFd** et la documentation pédagogique pour les
> formateurs (déroulé, solutions, anti-triche) sont gérés en interne par
> Humanix et ne sont pas publics.

---

## 🎯 Vue d'ensemble pédagogique

- **20 challenges**, difficulté croissante, OWASP Top 10 2021.
- **Hints gratuits** (3 par challenge) côté CTFd.
- **Flags** au format `HUMANIX{snake_case}` :
  - Mode **statique** (défaut) : mêmes flags pour tous, simple à corriger.
  - Mode **unique par élève** (`STUDENT_ID` activé) : flags dérivés par
    HMAC, anti-triche fort. Voir [`vulnapp/README.md`](vulnapp/README.md).
- Aucun outil offensif lourd requis : **navigateur + DevTools + `curl`**.

---

## ⚠️ Bonnes pratiques de sécurité

- La vulnapp est **délibérément faillible**. Le `docker-compose.yml`
  fourni la bind sur `127.0.0.1` uniquement. Ne JAMAIS l'exposer sur
  Internet ni sur un réseau partagé.
- Le service interne SSRF (port 8081) reste lié à `127.0.0.1` à
  l'intérieur du conteneur — jamais publié.
- Ne pousse jamais ta propre instance modifiée sur un domaine public.

---

## 📜 Licence & contributions

Projet pédagogique Humanix Cybersecurity. Utilisable et adaptable librement
pour des cours d'initiation. Mentionner la source en cas de réutilisation
publique.

Issues, PRs bienvenues —
<https://github.com/Humanix-Cybersecurity/CTF_Apprentis/issues>.
