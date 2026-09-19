#!/usr/bin/env python3
"""
Network Packet Analyzer - Outil d'analyse réseau pour SOC N1
Auteur: [Ton Nom]
Usage: python main.py --live [interface] | --file [capture.pcap]
"""

import argparse
import sys
from scapy.all import sniff, rdpcap
from src.sniffer import PacketAnalyzer
from src.detector import AnomalyDetector
from src.utils import print_colored, export_to_json

def analyze_live(interface=None, packet_count=100):
    """Capture et analyse en temps réel"""
    analyzer = PacketAnalyzer()
    
    print_colored(f"🎯 Capture en cours sur l'interface {interface or 'par défaut'}...", "cyan")
    print_colored(f"📊 Capture de {packet_count} paquets (Appuie sur Ctrl+C pour arrêter)", "yellow")
    
    try:
        # Capture en temps réel
        packets = sniff(iface=interface, count=packet_count, timeout=30)
        
        for packet in packets:
            analyzer.analyze_packet(packet)
        
        # Exécute les détections
        detector = AnomalyDetector(analyzer)
        detector.run_all_checks()
        
        # Affiche le rapport
        analyzer.print_summary()
        
        # Exporte en JSON
        report = analyzer.get_report()
        export_to_json(report, "capture_report.json")
        
        return analyzer
        
    except KeyboardInterrupt:
        print_colored("\n⏹️  Capture interrompue par l'utilisateur", "yellow")
        analyzer.print_summary()
        return analyzer
    except Exception as e:
        print_colored(f"❌ Erreur: {e}", "red")
        return None

def analyze_file(file_path):
    """Analyse un fichier .pcap existant"""
    try:
        print_colored(f"📂 Lecture du fichier {file_path}...", "cyan")
        packets = rdpcap(file_path)
        
        analyzer = PacketAnalyzer()
        for packet in packets:
            analyzer.analyze_packet(packet)
        
        # Exécute les détections
        detector = AnomalyDetector(analyzer)
        detector.run_all_checks()
        
        # Affiche le rapport
        analyzer.print_summary()
        
        # Exporte en JSON
        report = analyzer.get_report()
        export_to_json(report, "capture_report.json")
        
        return analyzer
        
    except FileNotFoundError:
        print_colored(f"❌ Fichier {file_path} introuvable", "red")
        return None
    except Exception as e:
        print_colored(f"❌ Erreur lors de la lecture du fichier: {e}", "red")
        return None

def main():
    parser = argparse.ArgumentParser(description="Analyseur de paquets réseau pour SOC N1")
    parser.add_argument("--live", action="store_true", help="Mode capture en temps réel")
    parser.add_argument("--file", type=str, help="Chemin vers un fichier .pcap à analyser")
    parser.add_argument("--interface", type=str, help="Interface réseau (ex: eth0, wlan0)")
    parser.add_argument("--count", type=int, default=100, help="Nombre de paquets à capturer")
    
    args = parser.parse_args()
    
    # Vérifie qu'au moins un mode est sélectionné
    if not args.live and not args.file:
        parser.print_help()
        print_colored("\n⚠️  Utilise --live ou --file", "yellow")
        return
    
    # Exécute le mode sélectionné
    if args.live:
        analyze_live(args.interface, args.count)
    elif args.file:
        analyze_file(args.file)

if __name__ == "__main__":
    main()