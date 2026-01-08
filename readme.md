# gab-wifi – Portail captif UniFi avec authentification Google (OIDC)

## 🎯 Objectif du projet

**gab-wifi** est un portail captif externe pour un réseau Wi-Fi invité UniFi, permettant  
une **authentification via Google (OpenID Connect)**, tout en assurant :

- une **intégration propre avec UniFi** (External Captive Portal)
- une **traçabilité minimale conforme RGPD**
- une **séparation réseau** via un VLAN Guest
- un déploiement simple grâce à **Docker**

Le projet est conçu pour fonctionner avec une **Cloud Gateway Ultra (UniFi OS)**,  
mais reste adaptable à d’autres contrôleurs UniFi.

---

## 🧱 Architecture générale

### Composants principaux

- **Client Wi-Fi invité**
  - smartphone / laptop
  - navigateur ou captive network assistant (iOS / Android)

- **Contrôleur Wi-Fi UniFi**
  - SSID invité sur VLAN Guest
  - Captive Portal activé
  - Redirection vers un portail externe

- **Portail d’authentification (Node.js)**
  - Express.js
  - Authentification Google via OpenID Connect
  - Enregistrement des logs RGPD
  - Appel API UniFi pour autoriser le client

- **Google Identity Platform**
  - Fournisseur d’identité (OIDC)

- **DuckDNS + Let’s Encrypt**
  - Nom de domaine public
  - Certificat TLS valide (HTTPS obligatoire)

- **Base de données PostgreSQL**
  - Stockage des événements d’authentification
  - Politique de rétention configurable

---

## 🔐 Pourquoi HTTPS est indispensable

Même si **Google ne se connecte jamais directement au portail**,  
le flux OAuth/OpenID impose :

- un **callback HTTPS**
- des **cookies sécurisés**
- une compatibilité avec les navigateurs captifs mobiles

👉 Le portail est donc exposé en **HTTPS (443)** via un reverse proxy  
(Nginx + Let’s Encrypt).

---

## 🔄 Flux d’authentification (diagramme de séquence)

```mermaid
sequenceDiagram
  autonumber
  actor Client as Client (téléphone/laptop)
  participant AP as Contrôleur Wi-Fi (UniFi)
  participant DNS as DuckDNS
  participant Nginx as Reverse Proxy (HTTPS)
  participant Portal as Portail Node.js
  participant Google as Google OIDC

  Client->>AP: Connexion au SSID invité (VLAN Guest)
  AP-->>Client: IP + DNS (accès restreint)
  Client->>AP: Requête web
  AP-->>Client: Redirection Captive Portal (302)

  Client->>DNS: Résolution gab-wifi.duckdns.org
  DNS-->>Client: Adresse IP du portail
  Client->>Nginx: GET https://gab-wifi.duckdns.org
  Nginx->>Portal: Proxy HTTP interne (port 3000)

  Portal-->>Client: Page captive + information RGPD
  Client->>Portal: Consentement + démarrage login

  Portal-->>Client: Redirection vers Google (OIDC)
  Client->>Google: Authentification Google
  Google-->>Client: Redirect vers callback du portail

  Client->>Portal: GET /auth/google/callback
  Portal->>Google: Échange code → ID token
  Google-->>Portal: ID token (sub, email…)

  Portal->>Portal: Validation du token
  Portal->>Portal: Log RGPD (identité + MAC + horodatage)

  Portal->>AP: API UniFi – authorize-guest(MAC)
  AP-->>Portal: OK

  Portal-->>Client: Accès Internet autorisé
  Client->>AP: Navigation Internet normale
