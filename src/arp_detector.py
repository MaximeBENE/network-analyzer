"""
Détecteur d'ARP Spoofing.
Surveille la table ARP et détecte les changements de MAC suspects.
"""

from scapy.all import ARP, sniff, getmacbyip
from collections import defaultdict
from datetime import datetime
from .utils import print_colored, is_private_ip


class ARPSpoofDetector:
    """
    Détecte les tentatives d'ARP Spoofing en surveillant les réponses ARP.

    Principe :
    - On mémorise la première MAC vue pour chaque IP
    - Si une IP change de MAC, c'est suspect (attaque MITM probable)
    - On garde un historique des changements pour analyse
    """

    def preload_arp_table(self):
        """
        Pré-remplit la table ARP avec les vraies MACs
        avant de commencer la surveillance.
        """
        import subprocess

        try:
            result = subprocess.run(
                ["ip", "neigh"],
                capture_output=True,
                text=True,
                timeout=2,
            )
            for line in result.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 5 and "lladdr" in parts:
                    ip = parts[0]
                    mac_idx = parts.index("lladdr") + 1
                    mac = parts[mac_idx].lower()
                    self.arp_table[ip] = mac
                    print_colored(f"📌 Pré-chargé : {ip} → {mac}", "blue")
        except Exception as e:
            print_colored(f"⚠️  Impossible de pré-charger la table ARP : {e}", "yellow")

    def __init__(self, interface=None):
        self.interface = interface
        # Table ARP légitime : {ip: mac}
        self.arp_table = {}
        # Historique des changements : {ip: [(timestamp, ancienne_mac, nouvelle_mac), ...]}
        self.changes = defaultdict(list)
        # Alertes générées
        self.alerts = []
        # Statistiques
        self.stats = {
            "total_arp": 0,
            "total_replies": 0,
            "total_requests": 0,
            "suspicious": 0,
        }

    def analyze_packet(self, packet):
        """Analyse un paquet ARP"""
        if not packet.haslayer(ARP):
            return

        self.stats["total_arp"] += 1
        arp = packet[ARP]
        src_ip = arp.psrc
        src_mac = arp.hwsrc
        dst_ip = arp.pdst
        op = arp.op  # 1 = request, 2 = reply

        if op == 1:
            self.stats["total_requests"] += 1
            return  # On ignore les requêtes, on analyse les réponses

        if op == 2:
            self.stats["total_replies"] += 1
            self._check_arp_reply(src_ip, src_mac, dst_ip)

    def _check_arp_reply(self, ip, mac, target_ip):
        """
        Vérifie si une réponse ARP est suspecte.

        Signature d'une attaque ARP Spoofing :
        - Une même IP change de MAC plusieurs fois
        - Surtout si l'IP cible est une passerelle (routeur)
        """
        mac = mac.lower()

        if ip not in self.arp_table:
            # Première fois qu'on voit cette IP → on enregistre
            self.arp_table[ip] = mac
            return

        if self.arp_table[ip] == mac:
            # Même MAC → pas de changement, RAS
            return

        # Changement de MAC détecté → SUSPECT
        old_mac = self.arp_table[ip]
        timestamp = datetime.now().strftime("%H:%M:%S")

        self.changes[ip].append({
            "timestamp": timestamp,
            "old_mac": old_mac,
            "new_mac": mac,
            "target_ip": target_ip,
        })

        self.stats["suspicious"] += 1

        # Génère une alerte
        severity = "🚨 CRITIQUE" if self._is_gateway(ip) else "⚠️  ÉLEVÉ"
        alert = (
            f"{severity} - ARP SPOOFING potentiel : "
            f"l'IP {ip} a changé de MAC ({old_mac} → {mac})"
        )

        # Détail supplémentaire
        detail = f"   La cible {target_ip} est visée. Possible Man-in-the-Middle."

        self.alerts.append(alert)
        print_colored(alert, "red")
        print_colored(detail, "yellow")

        # Met à jour la table avec la nouvelle MAC
        self.arp_table[ip] = mac

    def _is_gateway(self, ip):
        """
        Vérifie si l'IP est la passerelle par défaut du système.

        Lit la route par défaut avec ``ip route`` et utilise une heuristique
        simple en fallback.
        """
        # Essaie de détecter la vraie passerelle
        try:
            import subprocess

            result = subprocess.run(
                ["ip", "route", "show", "default"],
                capture_output=True,
                text=True,
                timeout=2,
            )
            # Exemple : "default via 192.168.244.2 dev eth1 ..."
            if "default via" in result.stdout:
                gateway_ip = result.stdout.split("via")[1].strip().split()[0]
                return ip == gateway_ip
        except Exception:
            pass

        # Fallback : heuristique sur les terminaisons classiques
        return ip.endswith(".1") or ip.endswith(".254")

    def start_sniffing(self, timeout=30, count=None):
        """
        Lance la capture ARP en temps réel.
        Nécessite sudo sur Linux, admin + Npcap sur Windows.
        """
        print_colored(
            f"🎯 Surveillance ARP sur l'interface {self.interface or 'par défaut'}...",
            "cyan",
        )
        print_colored(
            f"⏱️  Durée : {timeout}s (Ctrl+C pour arrêter)",
            "yellow",
        )
        
        # NOUVEAU : pré-charge la table ARP
        self.preload_arp_table()

        try:
            sniff(
                iface=self.interface,
                filter="arp",
                prn=self.analyze_packet,
                timeout=timeout,
                store=False,
            )
        except KeyboardInterrupt:
            print_colored("\n⏹️  Capture interrompue", "yellow")
        except Exception as e:
            print_colored(f"❌ Erreur : {e}", "red")
            print_colored(
                "💡 Sur Linux, lance avec sudo. Sur Windows, installe Npcap.",
                "yellow",
            )

    def get_report(self):
        """Génère un rapport d'analyse"""
        return {
            "total_arp_packets": self.stats["total_arp"],
            "total_replies": self.stats["total_replies"],
            "total_requests": self.stats["total_requests"],
            "arp_table_size": len(self.arp_table),
            "suspicious_changes": self.stats["suspicious"],
            "alerts": self.alerts,
            "changes_detail": dict(self.changes),
        }

    def print_summary(self):
        """Affiche un résumé dans le terminal"""
        print("\n" + "=" * 60)
        print_colored("📊 RAPPORT ARP SPOOFING", "cyan", bold=True)
        print("=" * 60)

        print_colored(f"\n📦 Paquets ARP analysés : {self.stats['total_arp']}", "white")
        print_colored(f"   Requêtes : {self.stats['total_requests']}", "white")
        print_colored(f"   Réponses : {self.stats['total_replies']}", "white")

        print_colored(f"\n📋 Taille table ARP : {len(self.arp_table)} entrées", "blue")

        if self.stats["suspicious"] == 0:
            print_colored("\n✅ Aucun changement de MAC détecté", "green")
            print_colored("   → Réseau sain (pas d'ARP Spoofing détecté)", "green")
        else:
            print_colored(
                f"\n⚠️  {self.stats['suspicious']} changements suspects détectés",
                "red",
                bold=True,
            )
            for alert in self.alerts:
                print(f"  • {alert}")

        print("\n" + "=" * 60)