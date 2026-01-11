# Gab WiFi – Portail captif UniFi avec authentification Google (OIDC)

Ce projet implémente un **portail captif WiFi auto‑hébergé** pour UniFi (Cloud Gateway Ultra / UniFi OS),
permettant l’authentification des invités via **Google OpenID Connect**, avec journalisation conforme RGPD
et interface d’administration protégée par mot de passe.

---

## 🎯 Objectifs
- Authentifier les invités WiFi via un compte Google
- Autoriser automatiquement les clients via l’API UniFi
- Journaliser les connexions (audit / RGPD)
- Hébergement local, déploiement Docker
- Administration simple via une page protégée

---

## 🧱 Architecture globale

```mermaid
flowchart LR
    Client["Client WiFi"]
    AP["UniFi AP"]
    Portal["Portail Captif (Node.js)"]
    Google["Google OIDC"]
    UniFi["UniFi Gateway / Controller"]
    DB["PostgreSQL"]
    Nginx["Nginx HTTPS"]

    Client --> AP --> Portal
    Portal --> Google
    Google --> Portal
    Portal --> UniFi
    Portal --> DB
    Nginx --> Portal
```

---

## 🔁 Diagramme de séquence

```mermaid
sequenceDiagram
    participant C as Client
    participant U as UniFi
    participant P as Portail
    participant G as Google
    participant D as DB

    C->>U: Connexion SSID invité
    U->>C: Redirection captive
    C->>P: GET /
    P->>C: Page portail
    C->>P: POST /start
    P->>G: Redirection OAuth2
    G->>P: Callback OIDC
    P->>U: authorize-guest
    P->>D: Enregistrement log
    P->>C: Accès Internet
```

---

## 📁 Structure du projet

```
gab-wifi/
├── portal/
│   ├── src/
│   │   ├── app.js        # Application principale
│   │   ├── oidc.js       # Authentification Google
│   │   ├── unifi.js      # API UniFi (authorize-guest)
│   │   ├── db.js         # Base PostgreSQL
│   │   └── views/        # Pages HTML
│   ├── Dockerfile
│   └── package.json
├── nginx/
│   └── conf.d/
│       └── portal.conf
├── docker-compose.yml
├── .env.example
└── README.md
```

---

## 🔐 Page d’administration
- URL : `/admin`
- Protection : **Basic Auth (Node.js)**
- Données visibles :
  - date
  - email Google
  - MAC client
  - SSID
  - IP
  - résultat (SUCCESS / FAIL)

---

## ⚙️ Configuration UniFi requise

### SSID
- Sécurité : Open
- Activer **Guest Policy**
- Redirection externe vers :
  `https://gab-wifi.duckdns.org/`

### Walled Garden
Autoriser :
- `accounts.google.com`
- `oauth2.googleapis.com`
- `*.googleusercontent.com`
- domaine du portail

### Compte UniFi
- Compte **local** (pas SSO)
- Rôle : Super Admin (pour test)
- Utilisé uniquement par le portail

---

## 🚀 Déploiement

### Cloner le dépôt
```bash
git clone https://github.com/<user>/gab-wifi.git
cd gab-wifi
```

### Démarrer
```bash
docker compose up -d --build
```

### Logs
```bash
docker logs -f wifi_portal
```

### Arrêt
```bash
docker compose down
```

---

## 📜 RGPD
- Consentement explicite
- Données minimales
- Durée de rétention configurable
- Hébergement local

---

## 🧑‍💻 Auteur
Projet pédagogique et professionnel – Portail captif UniFi moderne et extensible.
