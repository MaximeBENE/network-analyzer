from scapy.all import sniff, rdpcap, IP, TCP, UDP, ICMP, Raw
from scapy.layers.inet6 import IPv6
from collections import defaultdict
import time
from datetime import datetime
from .utils import print_colored, format_timestamp

class PacketAnalyzer:
    """Analyseur de paquets réseau professionnel"""
    
    def __init__(self):
        self.packets = []
        self.stats = {
            "total": 0,
            "tcp": 0,
            "udp": 0,
            "icmp": 0,
            "other": 0,
            "ips": defaultdict(int),
            "ports": defaultdict(int),
            "suspicious": []
        }
        self.start_time = time.time()
    
    def analyze_packet(self, packet):
        """Analyse un paquet et extrait les informations pertinentes"""
        self.stats["total"] += 1
        
        packet_info = {
            "timestamp": format_timestamp(time.time()),
            "src_ip": None,
            "dst_ip": None,
            "protocol": "Unknown",
            "src_port": None,
            "dst_port": None,
            "flags": None,
            "size": len(packet),
            "payload": None
        }
        
        # Récupère l'IP (supporte IPv4 et IPv6)
        if IP in packet:
            packet_info["src_ip"] = packet[IP].src
            packet_info["dst_ip"] = packet[IP].dst
            ip_layer = packet[IP]
        elif IPv6 in packet:
            packet_info["src_ip"] = packet[IPv6].src
            packet_info["dst_ip"] = packet[IPv6].dst
            ip_layer = packet[IPv6]
        else:
            # Paquet non-IP (ex: ARP)
            self.stats["other"] += 1
            return packet_info
        
        # Comptage des IPs
        self.stats["ips"][packet_info["src_ip"]] += 1
        
        # Analyse du protocole de transport
        if TCP in packet:
            self.stats["tcp"] += 1
            packet_info["protocol"] = "TCP"
            packet_info["src_port"] = packet[TCP].sport
            packet_info["dst_port"] = packet[TCP].dport
            packet_info["flags"] = packet[TCP].flags
            
            # Détection des flags suspects
            flags = packet[TCP].flags
            if flags & 0x02:  # SYN
                self.stats["ports"][packet_info["dst_port"]] += 1
            
            # Récupère le payload si présent
            if Raw in packet:
                packet_info["payload"] = bytes(packet[Raw]).decode('utf-8', errors='ignore')[:100]
                
        elif UDP in packet:
            self.stats["udp"] += 1
            packet_info["protocol"] = "UDP"
            packet_info["src_port"] = packet[UDP].sport
            packet_info["dst_port"] = packet[UDP].dport
            
            if Raw in packet:
                packet_info["payload"] = bytes(packet[Raw]).decode('utf-8', errors='ignore')[:100]
                
        elif ICMP in packet:
            self.stats["icmp"] += 1
            packet_info["protocol"] = "ICMP"
            packet_info["type"] = packet[ICMP].type
            packet_info["code"] = packet[ICMP].code
        else:
            self.stats["other"] += 1
        
        self.packets.append(packet_info)
        return packet_info
    
    def get_report(self):
        """Génère un rapport complet de l'analyse"""
        duration = time.time() - self.start_time
        
        # Top 10 des IPs les plus actives
        top_ips = sorted(self.stats["ips"].items(), key=lambda x: x[1], reverse=True)[:10]
        
        # Top 10 des ports les plus sollicités
        top_ports = sorted(self.stats["ports"].items(), key=lambda x: x[1], reverse=True)[:10]
        
        report = {
            "duration_seconds": round(duration, 2),
            "total_packets": self.stats["total"],
            "protocols": {
                "TCP": self.stats["tcp"],
                "UDP": self.stats["udp"],
                "ICMP": self.stats["icmp"],
                "Other": self.stats["other"]
            },
            "top_ips": top_ips,
            "top_ports": top_ports,
            "suspicious_events": self.stats["suspicious"]
        }
        
        return report
    
    def print_summary(self):
        """Affiche un résumé formaté dans le terminal"""
        report = self.get_report()
        
        print("\n" + "="*60)
        print_colored("📊 RAPPORT D'ANALYSE RÉSEAU", "cyan", bold=True)
        print("="*60)
        
        print_colored(f"\n⏱️  Durée: {report['duration_seconds']} secondes", "yellow")
        print_colored(f"📦 Paquets capturés: {report['total_packets']}", "white")
        
        print_colored("\n📈 Répartition des protocoles:", "blue")
        for proto, count in report["protocols"].items():
            if count > 0:
                percentage = (count / report['total_packets']) * 100
                bar = "█" * int(percentage / 5)
                print(f"  {proto}: {count} ({percentage:.1f}%) {bar}")
        
        print_colored("\n🌐 Top 5 IPs les plus actives:", "magenta")
        for ip, count in report["top_ips"][:5]:
            print(f"  {ip} → {count} paquets")
        
        print_colored("\n🔌 Top 5 ports les plus sollicités:", "magenta")
        for port, count in report["top_ports"][:5]:
            service = self._get_port_service(port)
            print(f"  Port {port} ({service}) → {count} connexions")
        
        if report["suspicious_events"]:
            print_colored("\n⚠️  ÉVÉNEMENTS SUSPECTS DÉTECTÉS:", "red", bold=True)
            for event in report["suspicious_events"]:
                print(f"  • {event}")
        else:
            print_colored("\n✅ Aucun événement suspect détecté", "green")
        
        print("\n" + "="*60)
    
    def _get_port_service(self, port):
        """Retourne le service associé à un port connu"""
        services = {
            20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet",
            25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3",
            123: "NTP", 143: "IMAP", 443: "HTTPS", 445: "SMB",
            993: "IMAPS", 995: "POP3S", 3306: "MySQL", 3389: "RDP",
            5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt"
        }
        return services.get(port, "Unknown")