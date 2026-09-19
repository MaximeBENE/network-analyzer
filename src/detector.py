from collections import defaultdict
from .utils import print_colored, is_private_ip


class AnomalyDetector:
    """Détecte les comportements suspects dans le trafic réseau"""

    def __init__(self, analyzer):
        self.analyzer = analyzer
        self.thresholds = {
            "port_scan": 20,      # Nombre de ports différents pour alerter
            "brute_force": 20,    # Nombre de SYN sur un même port
        }

    def detect_port_scan(self):
        """
        Détecte un scan de ports :
        - Beaucoup de ports distincts
        - Depuis une même IP source
        """
        MIN_PORTS = self.thresholds["port_scan"]

        ip_connections = defaultdict(set)

        for packet in self.analyzer.packets:
            if packet["protocol"] == "TCP" and packet["dst_port"] and packet["src_ip"]:
                ip_connections[packet["src_ip"]].add(packet["dst_port"])

        for ip, ports in ip_connections.items():
            if len(ports) >= MIN_PORTS:
                # Sévérité selon le nombre de ports
                if len(ports) >= 100:
                    severity = "🚨 CRITIQUE"
                elif len(ports) >= 50:
                    severity = "⚠️  ÉLEVÉ"
                else:
                    severity = "⚠️  MOYEN"

                # Scope : interne (RFC1918) ou externe
                scope = "interne" if is_private_ip(ip) else "EXTERNE"
                extra = "" if is_private_ip(ip) else " 🌍"

                alert = f"{severity} - SCAN DE PORTS ({scope}){extra} depuis {ip} - {len(ports)} ports distincts"
                self.analyzer.stats["suspicious"].append(alert)
                print_colored(alert, "red")

    def detect_brute_force(self):
        """
        Détecte une tentative de brute-force (beaucoup de SYN sur le même port sensible)
        """
        # Ports qui génèrent naturellement beaucoup de trafic (faux positifs connus)
        WHITELIST_PORTS = {53, 80, 443, 123, 5353}

        # Ports classiquement ciblés par du brute-force
        TARGET_PORTS = {21, 22, 23, 25, 110, 143, 445, 993, 995, 3306, 3389, 5432, 5900, 6379}

        connections = defaultdict(int)

        for packet in self.analyzer.packets:
            if packet["protocol"] != "TCP":
                continue
            if not packet["src_ip"] or not packet["dst_port"]:
                continue

            # Filtre les ports whitelistés
            if packet["dst_port"] in WHITELIST_PORTS:
                continue
            # Ne regarde QUE les ports sensibles
            if packet["dst_port"] not in TARGET_PORTS:
                continue
            # Uniquement les paquets SYN
            if packet["flags"] and packet["flags"] & 0x02:
                key = (packet["src_ip"], packet["dst_port"])
                connections[key] += 1

        for (ip, port), count in connections.items():
            if count >= self.thresholds["brute_force"]:
                service = self.analyzer._get_port_service(port)
                scope = "interne" if is_private_ip(ip) else "EXTERNE"
                extra = "" if is_private_ip(ip) else " 🌍"
                alert = f"🔒 BRUTE-FORCE potentiel ({scope}){extra} : {ip} → port {port} ({service}) - {count} tentatives SYN"
                self.analyzer.stats["suspicious"].append(alert)
                print_colored(alert, "yellow")

    def run_all_checks(self):
        """Exécute toutes les détections"""
        print_colored("\n🔍 Exécution des analyses de sécurité...", "blue")
        self.detect_port_scan()
        self.detect_brute_force()