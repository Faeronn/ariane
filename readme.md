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
| GET     | /auth/verify    | Vérification email   |
| POST    | /auth/refresh   | Nouveau access token |
| POST    | /auth/logout    | Révocation refresh   |

#### 🖥️ Inventaire [W.I.P]

| Méthode | Route                 | Description                  |
|---------|-----------------------|------------------------------|
| POST    | /agents/inventory     | Envoi snapshot machine       |
| GET     | /machines             | Liste des machines           |
| GET     | /machines/:id         | Détails machine              |
| GET     | /machines/:id/vulns   | Vulnérabilités détectées     |


## 🧪 Tests
```
npm test
```

## 🚀 Roadmap
- Sync automatique NVD/CVE
- Alertes email / Slack ? / Discord ? / ???
- RBAC multi-utilisateurs

## 🤝 Contribution
Promis j'essaie de vous répondre avant l'année prochaine.

## 📜 Licence
MIT © 2026