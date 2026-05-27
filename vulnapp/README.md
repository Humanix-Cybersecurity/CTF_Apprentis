# Vulnapp — La Carte au Trésor 🗺️

Ton terrain de jeu **local**. 20 vulnérabilités OWASP Top 10 à découvrir,
une par une, dans une appli Flask volontairement faillible.

> ⚠️ Cette application est **délibérément vulnérable**. Elle ne doit
> **jamais** être exposée sur Internet ni sur un réseau partagé. Le
> docker-compose ne la publie que sur `127.0.0.1` — laisse-le ainsi.

---

## 🚀 Démarrage (1 commande)

Tu as besoin de **Docker** et **Docker Compose** (inclus avec Docker Desktop).

Depuis ce dossier :

```bash
docker compose up --build
```

Puis ouvre <http://localhost:8080> dans ton navigateur.

Pour arrêter : `Ctrl+C`, puis `docker compose down` pour nettoyer.

---

## 🎯 But du jeu

1. Visite l'app et explore les différentes pages.
2. Chaque vulnérabilité résolue te révèle un **flag** au format
   `HUMANIX{quelque_chose}`.
3. Recopie ce flag dans le **CTFd en ligne** que ton prof t'a partagé.
4. Le scoreboard te dira si c'était bon.

20 challenges × 100 pts = 2000 pts → ta note sur 20 = points ÷ 100.

Tu ne sais pas par où commencer ? Lis les **hints du CTFd** (ils sont
gratuits et progressifs : H1 oriente, H2 met sur la piste, H3 te donne
quasiment la solution).

---

## 🛡️ Mode anti-triche (optionnel)

Par défaut, l'app utilise des **flags statiques** identiques pour tous les
élèves — c'est plus simple pour démarrer.

Pour activer le mode **flags uniques par élève** (anti-copie entre voisins) :

1. Édite `docker-compose.yml`.
2. Renseigne la variable `STUDENT_ID` avec **ton identifiant** (donné par ton
   prof : email tronqué, prénom+nom, etc.). Exemple :
   ```yaml
   environment:
     STUDENT_ID: "p.dubois"
   ```
3. Recrée le conteneur :
   ```bash
   docker compose down -v   # -v supprime aussi la base SQLite
   docker compose up --build
   ```

Tes flags auront alors un suffixe HMAC unique (ex :
`HUMANIX{idor_profile_leak_a1b2c3d4}`). Le prof vérifie côté CTFd que tu as
soumis **tes** flags personnels.

---

## 🧰 Astuces utiles avant de commencer

- `F12` ouvre les **DevTools** de ton navigateur (onglet Console, Network,
  Application > Cookies, etc.). Indispensable.
- `Ctrl+U` affiche le **code source HTML** de la page courante.
- L'URL d'une page est une **donnée** : tu peux la modifier à la main.
- `curl http://localhost:8080/...` est ton ami pour les endpoints API.
- Le mot « **debug** » est ton ami.

---

## 🆘 Problèmes courants

| Symptôme | Solution |
|---|---|
| Port 8080 déjà utilisé | Change `127.0.0.1:8080:8080` en `127.0.0.1:9090:8080` dans `docker-compose.yml`, puis va sur <http://localhost:9090>. |
| Page d'erreur Flask | C'est probablement voulu (les erreurs SQL font partie du jeu). Lis le message, il est révélateur. |
| Tu veux remettre l'app à zéro | `docker compose down -v && docker compose up --build` |
| Tu veux voir les routes existantes | Astuce : l'app a un endpoint de debug qui les liste toutes. À toi de le trouver 😉 |

---

## 🧪 Lancement sans Docker (alternative dev)

Si tu n'as pas Docker :

```bash
pip install -r requirements.txt
export DB_PATH=./data/vulnapp.sqlite
python app.py
```

Puis <http://localhost:8080>.

---

Bonne chasse, matelot. 🏴‍☠️
