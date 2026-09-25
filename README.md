# 🛡️ Network Packet Analyzer — SOC N1 Tool

![Python](https://img.shields.io/badge/Python-3.12+-blue?logo=python)
![Scapy](https://img.shields.io/badge/Scapy-2.5+-green)
![License](https://img.shields.io/badge/license-MIT-lightgrey)
![Status](https://img.shields.io/badge/status-active-success)

Outil d'analyse de trafic réseau développé en Python, conçu comme un **mini-IDS** (Intrusion Detection System) pour un usage **SOC Niveau 1**.

Il capture, analyse et détecte automatiquement des comportements suspects dans un fichier `.pcap`/`.pcapng` ou en temps réel sur une interface réseau.

---

## 🎯 Objectif du projet

Dans un SOC N1, l'analyste doit être capable de :

- Lire un flux réseau et en extraire les informations clés
- Détecter les scans de ports, brute-force, floods
- Prioriser les alertes selon le contexte (interne/externe, sévérité)
- Produire un rapport exploitable (JSON, logs, dashboard)

Ce projet **implémente ces briques** en Python, sans dépendre d'un SIEM lourd, pour démontrer la maîtrise des fondamentaux réseau et sécurité.

---

## 🛠️ Stack technique

| Composant | Rôle |
|:---|:---|
| **Python 3.12+** | Langage principal |
| **Scapy** | Capture et dissection des paquets |
| **Colorama** | Interface terminal colorée |

---

## ⚙️ Fonctionnalités

### Analyse

- Lecture de fichiers `.pcap` et `.pcapng`
- Capture live sur une interface réseau (Linux, nécessite `libpcap`)
- Extraction : IP source/dest, ports, protocole, flags TCP, taille, payload

### Détection

- 🚨 **Scan de ports** : plus de 20 ports distincts depuis une même IP
  - Sévérité graduée (MOYEN / ÉLEVÉ / CRITIQUE)
  - Distinction **interne** (RFC1918) vs **externe**
- 🔒 **Brute-force** : plus de 20 SYN sur un port sensible (SSH, RDP, MySQL…)
- 🕵️ **ARP Spoofing** : détection des changements de MAC suspects
  - Pré-chargement de la table ARP légitime au démarrage
  - Sévérité **CRITIQUE** si la cible est la passerelle par défaut
  - Identification automatique de la cible visée (MITM)
- 🛡️ **Whitelist** : exclusion des ports à fort trafic légitime (DNS, HTTP, NTP)
- 📊 **Rapport structuré** : résumé terminal + export JSON

---

## 📊 Exemples de sortie

### Analyse d'un fichier `.pcap`

```text
📂 Lecture du fichier captures/test.pcapng...

🔍 Exécution des analyses de sécurité...
🚨 CRITIQUE - SCAN DE PORTS (interne) depuis 192.168.149.129 - 1000 ports distincts

============================================================
📊 RAPPORT D'ANALYSE RÉSEAU
============================================================

⏱️  Durée: 0.09 secondes
📦 Paquets capturés: 2140

📈 Répartition des protocoles:
  TCP: 2058 (96.2%) ███████████████████
  UDP: 68 (3.2%)
  Other: 14 (0.7%)

🌐 Top 5 IPs les plus actives:
  192.168.149.130 → 1107 paquets
  192.168.149.129 → 1003 paquets
  192.168.149.1 → 15 paquets

🔌 Top 5 ports les plus sollicités:
  Port 53 (DNS) → 59 connexions
  Port 8888 (Unknown) → 1 connexions
  Port 110 (POP3) → 1 connexions
  Port 443 (HTTPS) → 1 connexions
  Port 25 (SMTP) → 1 connexions

⚠️  ÉVÉNEMENTS SUSPECTS DÉTECTÉS:
  • 🚨 CRITIQUE - SCAN DE PORTS (interne) depuis 192.168.149.129 - 1000 ports distincts

============================================================
✅ Exporté vers capture_report.json
```

### Détection d'ARP Spoofing

```text
🎯 Surveillance ARP sur l'interface eth1...
⏱️  Durée : 30s (Ctrl+C pour arrêter)

📌 Pré-chargé : 192.168.244.2 → 00:50:56:ed:cd:e9
📌 Pré-chargé : 192.168.244.128 → 00:0c:29:5a:f2:c6

🚨 CRITIQUE - ARP SPOOFING potentiel : l'IP 192.168.244.2 a changé de MAC
   (00:50:56:ed:cd:e9 → 00:0c:29:0a:94:2a)
   La cible 192.168.244.131 est visée. Possible Man-in-the-Middle.

============================================================
📊 RAPPORT ARP SPOOFING
============================================================

📦 Paquets ARP analysés : 19
   Requêtes : 2
   Réponses : 17

📋 Taille table ARP : 2 entrées

⚠️  1 changements suspects détectés
  • 🚨 CRITIQUE - ARP SPOOFING potentiel : l'IP 192.168.244.2 a changé de MAC
    (00:50:56:ed:cd:e9 → 00:0c:29:0a:94:2a)

============================================================
✅ Exporté vers arp_report.json
```

Le rapport est également exporté en JSON (`capture_report.json`, `arp_report.json`) pour intégration dans un SIEM.

---

## 🚀 Installation

### 1. Cloner le projet

```bash
git clone https://github.com/MaximeBENE/network-analyzer.git
cd network-analyzer
```

### 2. Créer un environnement virtuel

```bash
# Linux / Mac / WSL
python3 -m venv venv
source venv/bin/activate

# Windows PowerShell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

### 3. Installer les dépendances

```bash
python -m pip install --upgrade pip setuptools wheel
python -m pip install -r requirements.txt
```

> 💡 **Windows :** pour la capture live, installer [Npcap](https://npcap.com/#download) en cochant **"WinPcap API-compatible Mode"**.
> Pour l'analyse de fichiers `.pcap`, Npcap n'est pas nécessaire.

---

## 📖 Utilisation

### Analyser un fichier `.pcap` / `.pcapng`

```bash
python main.py --file captures/test.pcapng
```

### Capture live sur une interface (Linux)

```bash
# Nécessite sudo pour accéder à l'interface
sudo python main.py --live --interface eth0 --count 100
```

### Détecter un ARP Spoofing en temps réel (Linux)

```bash
sudo python main.py --arp --interface eth1 --timeout 30
```

**Fonctionnement :**

1. Pré-charge la table ARP légitime (via `ip neigh`)
2. Surveille les réponses ARP en temps réel
3. Détecte tout changement de MAC pour une même IP
4. Génère une alerte **CRITIQUE** si la cible est la passerelle

**Test avec `arpspoof` (dans un lab isolé) :**

```bash
# Terminal 1 — Détecteur
sudo python main.py --arp --interface eth1

# Terminal 2 — Attaque simulée
sudo arpspoof -i eth1 -t 192.168.244.128 192.168.244.2
```

---

## 🧪 Scénarios de test

| Scénario | Résultat attendu |
|:---|:---|
| Ping entre VMs | Rapport ICMP, aucune alerte |
| `nmap -p 1-1000` depuis Kali | 🚨 Scan détecté (CRITIQUE) |
| `hydra` SSH depuis Kali | 🔒 Brute-force détecté |
| `arpspoof` depuis Kali | 🕵️ ARP Spoofing détecté (CRITIQUE) |
| Navigation web normale | TCP/443 majoritaire, aucune alerte |

---

## 🗺️ Roadmap

- [x] Détection d'ARP spoofing
- [ ] Détection d'ICMP flood / Ping of Death
- [ ] Export vers format **Wazuh** / **Elasticsearch**
- [ ] Dashboard web (Flask + Chart.js)
- [ ] Tests unitaires (`pytest`)
- [ ] Support IPv6 complet
- [ ] Fichier de configuration (seuils ajustables en YAML)

---

## 🎓 Contexte

Projet développé dans le cadre d'une **reconversion vers la cybersécurité** (SOC N1 / Administration réseau), après plusieurs années en développement web.

L'objectif est de démontrer une double compétence :

- **Dev** : coder des outils propres, testables, documentés
- **Réseau/Sécu** : comprendre les protocoles, détecter les attaques, prioriser les alertes

---

## 📜 Licence

MIT — voir [LICENSE](./LICENSE).

---

## 👤 Auteur

**Maxime BENE**

- GitHub : [@MaximeBENE](https://github.com/MaximeBENE)
- Email : bene.max31@gmail.com
- Portfolio : [maximebene.com](https://www.maximebene.com)

---

> *"Je code les outils que j'utilise pour défendre le réseau."*