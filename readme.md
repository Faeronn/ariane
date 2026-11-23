# 🛡️ Vulnerability & Software Inventory Tracker
Outil d’inventaire logiciel et de suivi de vulnérabilités (CVE) pour machines Linux & Windows.

## ✨ Fonctionnalités
- 🔐 Authentification JWT + Refresh Token
- 📧 Vérification d’email à l’inscription
- 🏢 Organisations par domaine email, rôles admin / viewer
- 🖥️ Gestion d’une flotte de machines (enrôlement, clé agent par machine)
- 🧠 Normalisation logiciel → CPE → CVE (NVD API 2.0), alias des logiciels courants
- 🚨 Détection des vulnérabilités par version installée et par plateforme
- 🔔 Alertes des nouvelles CVE par email, Slack ou Discord
- 📊 API REST prête pour dashboard (résumé de flotte)

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

### 3️⃣ Créer la base de données
```
mysql -u root -p -e "CREATE DATABASE ariane CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
npm run migrate
```
Le schéma vient des fichiers de `migrations/`, appliqués dans l’ordre et une seule fois (table `schema_migrations`). `npm run migrate` met aussi à jour une base existante sans la recréer : une base importée de l’ancien `ariane.sql` est reconnue telle quelle. Un changement de schéma = un nouveau fichier `migrations/NNN-description.sql`.

`npm run migrate` utilise l’utilisateur du `.env` : il lui faut les droits de modifier le schéma (`CREATE`, `ALTER`, `INDEX`, `REFERENCES`, `DROP`).

Sauvegarder la base avant une migration, avec l’utilisateur applicatif (sans droit `LOCK TABLES`, d’où `--single-transaction`) :
```
mariadb-dump --single-transaction -u ariane -p ariane > ariane-backup.sql
```

### 4️⃣ Variables d’environnement

Copier `.env.example` en `.env` et le compléter : chaque variable y est commentée.
```
cp .env.example .env
```
Au démarrage, le serveur vérifie la configuration et refuse de démarrer s’il manque une valeur indispensable (base, secrets JWT, SMTP) ou si `MAIL_TRANSPORT=json` est utilisé en production : les codes de vérification ne partiraient jamais. Sans `NVD_API_KEY`, il démarre mais prévient que la résolution CPE/CVE sera lente (5 requêtes NVD / 30 s au lieu de 50).

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

Les routes d’authentification sont limitées en débit (connexion : 10 essais / 15 min par compte et 50 par adresse IP ; inscription : 5 / h ; vérification : 10 / 15 min). Au-delà : `429 { "message": "Error : Too many requests." }` avec l’en-tête `Retry-After`.

#### 🏢 Organisations et rôles

Chaque domaine email autorisé (table `domain`) appartient à une organisation : un utilisateur rejoint à l’inscription l’organisation de son domaine, et ne voit que les machines de son organisation. Le premier utilisateur vérifié d’une organisation en devient `admin`, les suivants sont `viewer` (lecture seule). Seuls les admins enrôlent, révoquent et changent les rôles.

| Méthode | Route            | Rôle   | Description |
|---------|------------------|--------|-------------|
| GET     | /users           | membre | Membres de l’organisation |
| PATCH   | /users/:id/role  | admin  | `{ "role": "admin" \| "viewer" }` ; une organisation garde toujours au moins un admin (sinon 409) |
| GET     | /organization/alerts | membre | Réglages d’alerte (URL du webhook masquée pour les viewers) |
| PUT     | /organization/alerts | admin  | `{ "minSeverity": "LOW" \| "MEDIUM" \| "HIGH" \| "CRITICAL", "emailEnabled": true, "webhookKind": "slack" \| "discord" \| null, "webhookUrl": "https://hooks.slack.com/services/…" }` |

Toutes les 15 minutes, les CVE apparues sur une machine depuis le dernier passage sont envoyées aux admins vérifiés de l’organisation, en un seul email récapitulatif (100 CVE au plus, triées par machine), si leur sévérité atteint `minSeverity`. Une CVE pas encore notée par le NVD est toujours signalée. Au premier passage sur une machine, ses CVE déjà présentes sont enregistrées sans alerte. Si l’organisation a configuré un webhook Slack ou Discord, le même récapitulatif y est posté. Chaque canal est suivi séparément : un envoi qui échoue (webhook en panne, SMTP indisponible) est retenté au passage suivant, sans renvoyer ce qui est déjà parti sur l’autre canal.

Seules les URL de webhook Slack (`https://hooks.slack.com/services/…`) et Discord (`https://discord.com/api/webhooks/…`) sont acceptées : l’API n’envoie jamais de requête vers une autre adresse.

#### 🖥️ Inventaire

| Méthode | Route                 | Rôle   | Description                  |
|---------|-----------------------|--------|------------------------------|
| POST    | /machines             | admin  | Enrôlement : renvoie `machineID` et la clé agent (affichée une seule fois) |
| DELETE  | /machines/:id         | admin  | Révocation de la machine et de sa clé agent |
| POST    | /agents/inventory     | agent  | Envoi snapshot machine (30 / h par machine) |
| POST    | /agents/applications  | agent  | Envoi d’une application et de ses lockfiles (120 / h par machine) |
| GET     | /machines             | membre | Liste des machines           |
| GET     | /machines/:id         | membre | Détails machine              |
| GET     | /machines/:id/vulns   | membre | Vulnérabilités détectées     |
| GET     | /fleet/summary        | membre | Résumé de flotte : machines (actives, révoquées, sans nouvelles depuis 7 jours), applications, vulnérabilités (logiciels et dépendances) par sévérité, machines touchées, 10 CVE les plus répandues, logiciels sans CPE |
| GET     | /software/unmapped    | membre | Logiciels sans CPE des machines actives (dernier snapshot), du plus répandu au moins répandu : ce qui échappe à la détection |
| GET     | /applications         | membre | Applications de l’organisation (machine, nombre de paquets, dont directs) |
| GET     | /applications/:id     | membre | Paquets du dernier snapshot d’une application (écosystème, version, `direct`, `dev`) |
| GET     | /applications/:id/vulns | membre | Vulnérabilités des dépendances (NVD et OSV croisés, `sources`), `unscanned` : paquets pas encore vérifiés par OSV |

Les routes `/machines`, `/applications`, `/users`, `/software`, `/organization` et `/fleet` exigent `Authorization: Bearer <access token>`. Les routes `/agents` exigent l’en-tête `X-Agent-Key: <clé agent>` d’une machine enrôlée et non révoquée. La machine d’une autre organisation répond 404, comme un identifiant inconnu.

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

Payload de `POST /agents/applications` : une application de la machine et ses lockfiles bruts, lus par Ariane (5 Mo et 20 000 paquets max). Fichiers acceptés : `package-lock.json` (npm 7+, lockfileVersion 2 ou 3), `composer.lock` (avec `composer.json` facultatif pour distinguer les dépendances directes), `uv.lock`. Le nom de fichier peut être un chemin, seul son nom compte.
```json
{
  "name": "gesdoc2",
  "path": "C:\dev\gesdoc2",
  "lockfiles": [{ "filename": "package-lock.json", "content": "{ \"lockfileVersion\": 3, ... }" }]
}
```
Réponse `201 { "message": "Application received.", "applicationID": 3, "snapshotID": 7, "packages": 832 }`. Une application est identifiée par son nom sur sa machine ; chaque envoi crée un snapshot de tous ses paquets (directs et transitifs, marqués `direct` et `dev`).

Les logiciels reçus sont associés à un CPE puis à leurs CVE par des jobs NVD en tâche de fond (jamais pendant la requête). L’association procède dans cet ordre :
1. **Alias** : les logiciels courants (navigateurs, 7-Zip, Notepad++, VLC, PuTTY, Python, Git…) sont reconnus par leur nom (`migrations/003-software-aliases.sql`) et cherchés directement par vendeur, produit et version. Si le dictionnaire NVD ne connaît pas encore cette version précise, un CPE est construit pour elle et ses CVE sont trouvées par les plages de versions vulnérables.
2. **Nom nettoyé** : sinon, le nom affiché est nettoyé (architecture, langue, version, éditeur retirés : « Mozilla Firefox (x64 fr) » => `firefox`) puis cherché par mots-clés.

Réponse de `GET /machines/:id/vulns` (triée par score CVSS décroissant, une entrée par CVE) :
```json
{
  "message": "Vulnerabilities retrieved.",
  "vulnerabilities": [
    {
      "cveID": "CVE-2022-0778",
      "severity": "HIGH",
      "cvssScore": 7.5,
      "published": "2022-03-15T17:15:08Z",
      "versionNormalized": false,
      "platformDependent": false,
      "sources": ["nvd"],
      "software": [{ "name": "openssl", "version": "3.0.0" }]
    }
  ],
  "unmappedSoftware": 2
}
```
`unmappedSoftware` compte les logiciels du dernier snapshot sans CPE (pas encore résolus ou introuvables dans le NVD).

Les vulnérabilités d’une machine incluent celles des dépendances de ses applications (dernier snapshot de chaque application). Trois sources se croisent : le NVD (par CPE, pour les logiciels installés et les dépendances directes), OSV (pour toutes les dépendances) et Packagist (avis de sécurité des paquets Composer, ceux que lit `composer audit`). Une vulnérabilité trouvée par plusieurs n’apparaît qu’une fois ; `sources` dit qui l’a trouvée (`nvd`, `osv`, `packagist`). Une dépendance est listée avec son application et son écosystème : `{ "name": "express", "version": "4.17.1", "ecosystem": "npm", "application": "gesdoc2" }`. Un avis sans CVE garde son identifiant d’origine (`GHSA-…`, `PYSEC-…`, `PKSA-…`).

Chaque nuit, les snapshots plus anciens que `SNAPSHOT_RETENTION_DAYS` (90 jours par défaut) sont supprimés, sauf le dernier de chaque machine ; les logiciels, liens CPE et CVE que plus aucune machine n’utilise le sont aussi.

Les versions de paquets de distribution sont associées au CPE de leur version amont (`3.0.11-1~deb12u2` => `3.0.11` : epoch, révision de paquet et suffixe `+dfsg` retirés). Les distributions corrigent souvent une faille par rétroportage sans changer la version amont : `versionNormalized: true` signale une CVE trouvée uniquement par ce biais, à vérifier auprès de l’avis de sécurité de la distribution.

Certaines CVE ne s’appliquent que sur une plateforme donnée (« vulnérable seulement sous Windows »). Une telle CVE est retirée d’une machine dont le système (`osFamily`) n’est aucune des plateformes requises ; si la plateforme est inconnue ou correspond, la CVE reste listée avec `platformDependent: true`.


## 🧪 Tests
Les tests tournent sur une base MariaDB dédiée dont le nom finit par `_test` :
```
mysql -u root -p -e "CREATE DATABASE ariane_test CHARACTER SET utf8mb4; CREATE USER 'ariane_test'@'localhost' IDENTIFIED BY 'ariane_test'; GRANT ALL ON ariane_test.* TO 'ariane_test'@'localhost';"
cp .env.test.example .env.test
npm test                # suite complète
npm run test:coverage   # + couverture par fichier
```

## 🚀 Roadmap
- Agent de collecte (Linux / Windows)
- Dashboard web

## 🤝 Contribution
Promis j'essaie de vous répondre avant l'année prochaine.

## 📜 Licence
MIT © 2026