# Déployer votre propre serveur Garmin MCP

Ce guide vous permet de connecter **votre** compte Garmin à Claude (ou ChatGPT), sur **votre propre serveur**. Personne d'autre, y compris la personne qui vous a partagé ce lien, n'a accès à vos données.

Comptez environ **30 minutes**. Aucune compétence en programmation n'est nécessaire : il suffit de copier-coller quelques commandes.

---

## Sommaire

1. [Comment ça marche](#1-comment-ça-marche)
2. [Ce qu'il vous faut](#2-ce-quil-vous-faut)
3. [Étape 1 — Copier le projet sur votre GitHub](#étape-1--copier-le-projet-sur-votre-github)
4. [Étape 2 — Vous connecter à Garmin depuis votre ordinateur](#étape-2--vous-connecter-à-garmin-depuis-votre-ordinateur)
5. [Étape 3 — Créer le serveur sur Railway](#étape-3--créer-le-serveur-sur-railway)
6. [Étape 4 — Connecter Claude](#étape-4--connecter-claude)
7. [Sécurité : les bons réflexes](#sécurité--les-bons-réflexes)
8. [Options](#options)
9. [Mettre à jour](#mettre-à-jour)
10. [Dépannage](#dépannage)
11. [Limites à connaître](#limites-à-connaître)

---

## 1. Comment ça marche

```
Claude ──HTTPS──▶ Votre serveur Railway ──▶ Garmin Connect
          (protégé par votre mot de passe)    (avec vos tokens Garmin)
```

- **Votre serveur** tourne sur [Railway](https://railway.com), un hébergeur. Il n'est qu'à vous.
- **Il ne connaît pas votre mot de passe Garmin.** Vous vous connectez à Garmin une seule fois, sur votre ordinateur, et vous ne donnez au serveur que des **tokens** : des clés d'accès que Garmin renouvelle automatiquement.
- **Un mot de passe de serveur**, que vous choisissez, est demandé chaque fois qu'une application (Claude, ChatGPT…) veut se connecter à votre serveur. Sans lui, personne ne peut lire vos données, même en connaissant l'adresse.

> **Pourquoi se connecter à Garmin depuis son ordinateur ?** Garmin bloque les connexions venant des serveurs d'hébergement, et le code de vérification (MFA) ne peut pas être saisi sur un serveur. Faire la connexion chez vous règle les deux problèmes.

---

## 2. Ce qu'il vous faut

| | Détail |
|---|---|
| Un compte **GitHub** | Gratuit — [github.com/signup](https://github.com/signup) |
| Un compte **Railway** | [railway.com](https://railway.com) — l'offre *Hobby* coûte environ **5 $/mois**, largement suffisant pour ce serveur |
| Un compte **Claude** | Qui permet d'ajouter un *connecteur personnalisé* (vérifiez dans *Paramètres → Connecteurs*) |
| Votre compte **Garmin Connect** | Email, mot de passe, et votre téléphone/email si la double authentification est activée |
| Un **ordinateur** | Windows, macOS ou Linux, pour l'étape 2 |

---

## Étape 1 — Copier le projet sur votre GitHub

1. Connectez-vous à GitHub.
2. Ouvrez la page du projet (le lien qu'on vous a envoyé).
3. Cliquez sur **Fork** (en haut à droite), puis **Create fork**.

Vous avez maintenant votre propre copie : `https://github.com/VOTRE-PSEUDO/garmin_mcp`.

> Dans la suite, remplacez toujours `VOTRE-PSEUDO` par votre nom d'utilisateur GitHub.

---

## Étape 2 — Vous connecter à Garmin depuis votre ordinateur

### 2.1 Installer `uv` (outil qui lance le programme de connexion)

**Windows** — ouvrez **PowerShell** (touche Windows, tapez « PowerShell ») et collez :

```powershell
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
```

**macOS / Linux** — ouvrez le **Terminal** et collez :

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

Puis **fermez et rouvrez** la fenêtre PowerShell / Terminal.

### 2.2 Se connecter à Garmin

Collez cette commande (en remplaçant `VOTRE-PSEUDO`) :

```bash
uvx --python 3.12 --from https://github.com/VOTRE-PSEUDO/garmin_mcp/archive/refs/heads/main.zip garmin-mcp-auth
```

Le programme vous demande :
- votre **email Garmin** ;
- votre **mot de passe Garmin** (rien ne s'affiche quand vous tapez, c'est normal) ;
- le **code de vérification** reçu par email ou SMS, si la double authentification est activée.

À la fin, vous devez voir `✓ Authentication successful!`.

> Votre mot de passe Garmin n'est **pas** enregistré : seuls des tokens le sont, dans le dossier `.garminconnect` de votre ordinateur.

### 2.3 Récupérer la clé à donner au serveur

```bash
uvx --python 3.12 --from https://github.com/VOTRE-PSEUDO/garmin_mcp/archive/refs/heads/main.zip garmin-mcp-auth --export
```

La commande affiche une longue ligne de caractères (elle commence souvent par `eyJ`). **Copiez-la entièrement** : c'est la valeur de `GARMIN_TOKENS_JSON_BASE64` à l'étape 3.

> ⚠️ Cette clé donne accès à votre compte Garmin. Ne la collez nulle part ailleurs que dans Railway, ne l'envoyez à personne.

---

## Étape 3 — Créer le serveur sur Railway

### 3.1 Créer le projet

1. Connectez-vous sur [railway.com](https://railway.com) (le plus simple : *Login with GitHub*).
2. **New Project → Deploy from GitHub repo**.
3. Autorisez Railway à accéder à votre GitHub si on vous le demande, puis choisissez **`garmin_mcp`** (votre fork).

Un premier déploiement démarre et **va échouer** : c'est normal, il manque la configuration.

### 3.2 Choisir votre mot de passe de serveur

Il doit faire **au moins 12 caractères**. Le mieux : le faire générer par votre gestionnaire de mots de passe (Bitwarden, 1Password, trousseau iCloud…) et l'y enregistrer sous le nom « Serveur Garmin MCP ».

> Ce n'est **pas** votre mot de passe Garmin, et il ne doit pas lui ressembler.

### 3.3 Ajouter les variables

Cliquez sur votre service → onglet **Variables** → **Raw Editor**, et collez en remplaçant les valeurs :

```
GARMIN_MCP_ADMIN_PASSWORD=votre-mot-de-passe-de-serveur
GARMIN_TOKENS_JSON_BASE64=la-longue-clé-copiée-à-l'étape-2.3
PORT=3000
```

Cliquez sur **Update Variables**.

### 3.4 Ajouter un volume (indispensable)

Le volume est un petit disque qui garde vos tokens Garmin et vos connexions entre deux redémarrages. **Sans lui, tout est perdu à chaque mise à jour.**

1. Dans le projet, faites un **clic droit** sur votre service (ou `Ctrl/Cmd + K` puis tapez « Volume »).
2. **Attach volume** / **Add Volume**.
3. **Mount path** : `/data`

Le serveur détecte le volume tout seul, il n'y a rien d'autre à configurer.

### 3.5 Donner une adresse publique au serveur

1. Service → **Settings** → **Networking** → **Generate Domain**.
2. Si Railway demande un port, indiquez **3000**.

Vous obtenez une adresse du type `https://garmin-mcp-production-xxxx.up.railway.app`. Le serveur l'utilise automatiquement.

### 3.6 Vérifier

1. Onglet **Deployments** : le dernier déploiement doit être **Active** (vert). Sinon, cliquez sur **Redeploy**.
2. Ouvrez les **logs** du déploiement : vous devez voir
   ```
   Garmin token store ready at /data/garmin_tokens.json
   Public URL: https://....up.railway.app  (MCP endpoint: https://....up.railway.app/sse)
   ```
3. Dans votre navigateur, ouvrez `https://VOTRE-ADRESSE.up.railway.app/health` : la page doit afficher `{"status":"ok"}`.

---

## Étape 4 — Connecter Claude

1. Sur [claude.ai](https://claude.ai) : **Paramètres → Connecteurs → Ajouter un connecteur personnalisé**.
2. **Nom** : `Garmin` — **URL** : `https://VOTRE-ADRESSE.up.railway.app/sse` (n'oubliez pas le `/sse` à la fin).
3. Cliquez sur **Connecter**. Une page **« Autoriser l'accès à vos données Garmin »** s'ouvre.
4. Vérifiez que l'adresse dans la barre du navigateur est bien **la vôtre**, saisissez votre **mot de passe de serveur**, puis **Autoriser**.

Testez : *« Quelles sont mes 3 dernières activités Garmin ? »*

**Autres applications** (ChatGPT…) : si votre offre permet d'ajouter un connecteur MCP personnalisé, utilisez la même URL en `/sse` ; la même page de mot de passe s'affichera.

> Les menus de Claude, Railway et GitHub évoluent : si un intitulé diffère légèrement, cherchez l'option la plus proche.

---

## Sécurité : les bons réflexes

- **Un serveur = un compte Garmin.** Ne partagez jamais votre mot de passe de serveur : quiconque l'a peut lire (et modifier) **vos** données Garmin. Si un proche veut le service, il suit ce guide pour avoir son propre serveur.
- **Ne saisissez le mot de passe de serveur que sur la page de votre propre adresse** (`...up.railway.app` que vous avez générée).
- **Après 5 mots de passe faux**, la page se bloque 15 minutes : c'est une protection contre les attaques, pas une panne.
- **Si vous pensez que le mot de passe de serveur a fuité** : changez `GARMIN_MCP_ADMIN_PASSWORD` dans Railway. Les applications déjà connectées le restent jusqu'à expiration de leur accès ; pour les déconnecter immédiatement, supprimez le volume, recréez-le avec le même chemin `/data` et redéployez (les tokens Garmin sont recréés depuis `GARMIN_TOKENS_JSON_BASE64`), puis reconnectez Claude.
- **Si la clé `GARMIN_TOKENS_JSON_BASE64` a fuité** : changez votre mot de passe Garmin sur connect.garmin.com par précaution, refaites l'étape 2 avec `--force-reauth` et mettez la nouvelle clé dans la variable.
- **Pour limiter les risques**, activez le mode lecture seule (ci-dessous).

---

## Options

À ajouter dans l'onglet **Variables** de Railway (le serveur redémarre tout seul) :

| Variable | Effet |
|---|---|
| `GARMIN_MCP_READ_ONLY=true` | **Mode lecture seule** : l'IA peut lire vos données mais ne peut rien créer, modifier ni supprimer (séances, pesées, repas…). Recommandé si vous voulez seulement analyser vos données. |
| `GARMIN_DISABLED_TOOLS=delete_workouts,delete_weigh_ins` | Désactive des outils précis (liste séparée par des virgules). |
| `GARMIN_ENABLED_TOOLS=get_activities,get_sleep_data` | N'active **que** ces outils. |
| `BASE_URL=https://garmin.mon-domaine.fr` | Seulement si vous utilisez votre propre nom de domaine au lieu de l'adresse Railway. |

---

## Mettre à jour

Quand le projet d'origine reçoit des améliorations :

1. Sur **votre** fork GitHub, cliquez sur **Sync fork → Update branch**.
2. Railway redéploie automatiquement. Vos tokens et connexions sont conservés grâce au volume.

---

## Dépannage

| Symptôme | Cause probable et solution |
|---|---|
| Le déploiement échoue avec `GARMIN_MCP_ADMIN_PASSWORD must be set` | Variable manquante ou mot de passe de moins de 12 caractères (étape 3.3). |
| Logs : `WARNING: no Railway volume attached` | Le volume n'est pas branché (étape 3.4). |
| Logs : `ERROR: no Garmin login configured` | `GARMIN_TOKENS_JSON_BASE64` manquante ou vide (étapes 2.3 et 3.3). |
| `/health` ne répond pas | Vérifiez l'adresse (étape 3.5), le port **3000**, et que le déploiement est **Active**. |
| Claude affiche une erreur à la connexion | Vérifiez que l'URL se termine par **`/sse`**, et que `https://…/health` répond. |
| « Mot de passe incorrect » | C'est le **mot de passe de serveur** (variable Railway), pas celui de Garmin. |
| « Trop de tentatives échouées » | Attendez 15 minutes. |
| Les outils répondent `Garmin authentication expired` | Les tokens Garmin ne sont plus valides (changement de mot de passe Garmin, longue inactivité…). Refaites l'étape 2 (ajoutez `--force-reauth` à la commande de connexion), puis collez la nouvelle clé dans `GARMIN_TOKENS_JSON_BASE64` : une nouvelle valeur remplace automatiquement les anciens tokens. |
| `Too many requests` / `429` à l'étape 2 | Garmin limite les tentatives : attendez 15 à 30 minutes. |
| `uvx` : commande introuvable | Fermez et rouvrez le terminal après l'installation de `uv` (étape 2.1). |

Pour voir ce qui se passe : Railway → votre service → **Deployments** → **View logs**.

---

## Limites à connaître

- **API non officielle.** Ce projet utilise la bibliothèque communautaire [python-garminconnect](https://github.com/cyberjunky/python-garminconnect), qui imite l'application Garmin. Garmin peut la casser du jour au lendemain ; un correctif arrive alors en général via une mise à jour (voir *Mettre à jour*).
- **Données de santé.** Votre serveur transmet vos données (sommeil, fréquence cardiaque, poids…) à l'IA que vous connectez. Ne connectez que des applications de confiance.
- **Un seul serveur à la fois.** Ne passez pas le nombre de réplicas au-dessus de 1 sur Railway (déjà réglé dans `railway.toml`).
- **Coût.** Railway facture à l'usage ; ce serveur consomme peu, mais surveillez votre tableau de bord Railway le premier mois.
