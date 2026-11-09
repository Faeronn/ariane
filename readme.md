# 🛡️ Vulnerability & Software Inventory Tracker
Outil d’inventaire logiciel et de suivi de vulnérabilités (CVE) pour machines Linux & Windows.

## ✨ Fonctionnalités
- 🔐 Authentification JWT + Refresh Token
- 📧 Vérification d’email à l’inscription
- 🖥️ [ W.I.P ] Gestion d’une flotte de machines
- 🧠 [ W.I.P ] Normalisation logiciel → CPE → CVE
- 🚨 [ W.I.P ] Détection des vulnérabilités par version installée
- 📊 [ W.I.P ] API REST prête pour dashboard

## 🏗️ Stack technique

**Backend**
- Node.js + Express
- MariaDB
- JWT
- bcrypt

## 📁 Structure du projet
```bash
ariane/
├── routes/        # Endpoints Express
├── utils/         # Helpers
├── middleware/    # Middlewares
└── app.js         # Point d’entrée API
```

## ⚙️ Installation

### 1️⃣ Cloner le repo
```
git clone https://github.com/Faeronn/ariane.git
cd ariane
```

### 2️⃣ Installer les dépendances
```
npm install
```

### 3️⃣ Importer la base de données
```
mysql -u root -p -e "CREATE DATABASE ariane CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
mysql -u root -p ariane < ariane.sql
```

### 4️⃣ Variables d’environnement

Créer un fichier .env :
```
PORT=3000

DB_HOST=localhost
DB_HOST=3306
DB_USER=root
DB_PASSWORD=secret
DB_NAME=vuln_tracker

JWT_ACCESS_SECRET=change_me_access
JWT_REFRESH_SECRET=change_me_refresh

MAIL_HOST=smtp.example.com
MAIL_PORT=587
MAIL_USER=user
MAIL_PASS=password

# NVD (source des CPE/CVE). Sans clé : 5 requêtes / 30 s ; avec clé : 50 / 30 s.
# Clé gratuite : https://nvd.nist.gov/developers/request-an-api-key
NVD_API_KEY=
# false désactive les jobs NVD en tâche de fond (tests, dev hors ligne)
NVD_ENABLED=true
```

### 5️⃣ Lancer le serveur
```
npm run dev
```

### 📡 Endpoints principaux

#### 🔐 Auth

| Méthode | Route           | Description          |
|---------|-----------------|----------------------|
| POST    | /auth/signup    | Création utilisateur |
| POST    | /auth/signin    | Connexion            |
| GET     | /auth/verify?username=&code= | Vérification email (5 essais, 1 h) |
| POST    | /auth/refresh   | Nouveau access token |
| POST    | /auth/logout    | Révocation refresh   |

#### 🖥️ Inventaire [W.I.P]

| Méthode | Route                 | Description                  |
|---------|-----------------------|------------------------------|
| POST    | /machines             | Enrôlement : renvoie `machineID` et la clé agent (affichée une seule fois) |
| DELETE  | /machines/:id         | Révocation de la machine et de sa clé agent |
| POST    | /agents/inventory     | Envoi snapshot machine       |
| GET     | /machines             | Liste des machines           |
| GET     | /machines/:id         | Détails machine              |
| GET     | /machines/:id/vulns   | Vulnérabilités détectées     |

Les routes `/machines` exigent `Authorization: Bearer <access token>`. Les routes `/agents` exigent l’en-tête `X-Agent-Key: <clé agent>` d’une machine enrôlée et non révoquée.

Payload de `POST /agents/inventory` (5 Mo et 10 000 logiciels max ; `vendor` et `version` facultatifs) :
```json
{
  "hostname": "web-01",
  "osFamily": "linux",
  "osVersion": "Debian 12",
  "collectedAt": "2026-11-09T10:00:00Z",
  "software": [
    { "name": "openssl", "version": "3.0.0", "vendor": "openssl" }
  ]
}
```
Réponse `201 { "message": "Inventory received.", "snapshotID": 42 }`. Chaque envoi crée un snapshot ; l’état d’une machine est son dernier snapshot.


## 🧪 Tests
Les tests tournent sur une base MariaDB dédiée dont le nom finit par `_test` :
```
mysql -u root -p -e "CREATE DATABASE ariane_test CHARACTER SET utf8mb4; CREATE USER 'ariane_test'@'localhost' IDENTIFIED BY 'ariane_test'; GRANT ALL ON ariane_test.* TO 'ariane_test'@'localhost';"
cp .env.test.example .env.test
npm test                # suite complète
npm run test:coverage   # + couverture par fichier
```

## 🚀 Roadmap
- Sync automatique NVD/CVE
- Alertes email / Slack ? / Discord ? / ???
- RBAC multi-utilisateurs

## 🤝 Contribution
Promis j'essaie de vous répondre avant l'année prochaine.

## 📜 Licence
MIT © 2026