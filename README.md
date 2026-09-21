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
- Détecter les scans de ports, brute-force, floods, ARP Spoofing
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

### Analyse réseau
- Lecture de fichiers `.pcap` et `.pcapng`
- Capture live sur une interface réseau (Linux, nécessite `libpcap`)
- Extraction : IP source/dest, ports, protocole, flags TCP, taille, payload

### Détections automatiques
- 🚨 **Scan de ports** : plus de 20 ports distincts depuis une même IP
  - Sévérité graduée (MOYEN / ÉLEVÉ / CRITIQUE)
  - Distinction **interne** (RFC1918) vs **externe**
- 🔒 **Brute-force** : plus de 20 SYN sur un port sensible (SSH, RDP, MySQL…)
- 🛡️ **ARP Spoofing** : détection en temps réel des Man-in-the-Middle
  - Surveillance des réponses ARP
  - Alerte sur changement de MAC pour une IP connue
  - Détection intelligente de la passerelle (`ip route`)
  - Identification de la cible visée

### Rapports
- Rapport structuré en terminal (résumé + alertes)
- Export JSON compatible SIEM (Wazuh, Elasticsearch)

---

## 📊 Exemple de sortie

### Analyse d'un scan de ports

📂 Lecture du fichier captures\test.pcapng...

🔍 Exécution des analyses de sécurité...
🚨 CRITIQUE - SCAN DE PORTS (interne) depuis 192.168.149.129 - 1000 ports distincts

============================================================
📊 RAPPORT D'ANALYSE RÉSEAU
============================================================

⏱️ Durée: 0.09 secondes
📦 Paquets capturés: 2140

📈 Répartition des protocoles:
TCP: 2058 (96.2%) ███████████████████
UDP: 68 (3.2%)
Other: 14 (0.7%)

🌐 Top 5 IPs les plus actives:
192.168.149.130 → 1107 paquets
192.168.149.129 → 1003 paquets

🔌 Top 5 ports les plus sollicités:
Port 53 (DNS) → 59 connexions
...

⚠️ ÉVÉNEMENTS SUSPECTS DÉTECTÉS:
• 🚨 CRITIQUE - SCAN DE PORTS (interne) depuis 192.168.149.129 - 1000 ports distincts

### Détection d'ARP Spoofing

🎯 Surveillance ARP sur l'interface eth1...
⏱️ Durée : 30s (Ctrl+C pour arrêter)

🚨 CRITIQUE - ARP SPOOFING potentiel : l'IP 192.168.244.2 a changé de MAC (00:0c:29:5a:f2:c6 → 00:50:56:ed:cd:e9)
La cible 192.168.244.131 est visée. Possible Man-in-the-Middle.

============================================================
📊 RAPPORT ARP SPOOFING
============================================================

📦 Paquets ARP analysés : 20
Requêtes : 11
Réponses : 9

📋 Taille table ARP : 2 entrées

⚠️ 2 changements suspects détectés
• 🚨 CRITIQUE - ARP SPOOFING potentiel : l'IP 192.168.244.2 a changé de MAC

---

## 🏗️ Architecture
network-analyzer/
├── src/
│ ├── init.py
│ ├── sniffer.py # Capture + dissection des paquets
│ ├── detector.py # Détection scan de ports + brute-force
│ ├── arp_detector.py # Détection ARP Spoofing
│ └── utils.py # Helpers (couleurs, JSON, IP privée)
├── captures/ # Fichiers .pcap de test
├── tests/ # Tests unitaires (roadmap)
├── main.py # Point d'entrée CLI
├── requirements.txt
└── README.md

---

## 🚀 Installation

### 1. Cloner le projet

```bash
git clone https://github.com/MaximeBENE/network-analyzer.git
cd network-analyzer
2. Créer un environnement virtuel

# Linux / Mac / WSL
python3 -m venv venv
source venv/bin/activate

# Windows PowerShell
python -m venv venv
.\venv\Scripts\Activate.ps1

3. Installer les dépendances

python -m pip install --upgrade pip setuptools wheel
python -m pip install -r requirements.txt

💡 Windows : pour la capture live, installer Npcap en cochant "WinPcap API-compatible Mode". Pour l'analyse de fichiers .pcap, Npcap n'est pas nécessaire.

💡 Linux : la capture live nécessite sudo (accès aux interfaces réseau).

📖 Utilisation
Analyser un fichier .pcap / .pcapng

python main.py --file captures/test.pcapng

Capture live sur une interface (Linux)

# Nécessite sudo pour accéder à l'interface
sudo python main.py --live --interface eth0 --count 100
Détection ARP Spoofing en temps réel

# Nécessite sudo (accès aux interfaces réseau)
sudo python main.py --arp --interface eth0

Options :

--arp : lance le détecteur ARP Spoofing

--interface eth0 : précise l'interface à surveiller

Durée par défaut : 30 secondes (modifiable dans le code).

🧪 Scénarios de test
Scénario	Résultat attendu
Ping entre VMs	Rapport ICMP, aucune alerte
nmap -p 1-1000 depuis Kali	🚨 Scan détecté (CRITIQUE)
hydra SSH depuis Kali	🔒 Brute-force détecté
arpspoof sur la passerelle	🚨 ARP Spoofing détecté (CRITIQUE)
Navigation web normale	TCP/443 majoritaire, aucune alerte
Tester l'ARP Spoofing dans un lab
Pré-requis : deux VMs (Kali attaquant + Ubuntu cible) sur réseau Host-Only.

Sur Kali (détecteur) :

sudo python main.py --arp --interface eth1

Sur Ubuntu (attaquant) :

sudo apt install -y dsniff
sudo sysctl -w net.ipv4.ip_forward=1
sudo arpspoof -i ens33 -t <IP_KALI> <IP_PASSERELLE>

Résultat : alerte 🚨 CRITIQUE dans le terminal du détecteur.

🗺️ Roadmap
☑ Détection de scan de ports
☑ Détection de brute-force
☑ Détection d'ARP Spoofing
□ Détection d'ICMP flood / Ping of Death
□ Export vers format Wazuh / Elasticsearch
□ Dashboard web (Flask + Chart.js)
□ Tests unitaires (pytest)
□ Support IPv6 complet
□ Fichier de configuration (seuils ajustables en YAML)
🎓 Contexte
Projet développé dans le cadre d'une reconversion vers la cybersécurité (SOC N1 / Administration réseau), après plusieurs années en développement web.

L'objectif est de démontrer une double compétence :

Dev : coder des outils propres, testables, documentés

Réseau/Sécu : comprendre les protocoles, détecter les attaques, prioriser les alertes

🔗 Étude de cas détaillée : maximebene.com/projects/network-analyzer
🔗 Détecteur ARP Spoofing : maximebene.com/projects/arp-spoofing-detector

📜 Licence
MIT — voir LICENSE.

👤 Auteur
Maxime BENE

GitHub : @MaximeBENE

Portfolio : maximebene.com

Email : bene.max31@gmail.com