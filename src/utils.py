import json
import ipaddress
from datetime import datetime
from colorama import Fore, Style, init

# Initialise colorama pour Windows
init(autoreset=True)

def print_colored(message, color="white", bold=False):
    """Affiche un message coloré dans le terminal"""
    colors = {
        "red": Fore.RED,
        "green": Fore.GREEN,
        "yellow": Fore.YELLOW,
        "blue": Fore.BLUE,
        "magenta": Fore.MAGENTA,
        "cyan": Fore.CYAN,
        "white": Fore.WHITE
    }
    prefix = Style.BRIGHT if bold else ""
    print(f"{prefix}{colors.get(color, Fore.WHITE)}{message}{Style.RESET_ALL}")

def export_to_json(data, filename="report.json"):
    """Exporte les résultats en JSON"""
    with open(filename, 'w') as f:
        json.dump(data, f, indent=2, default=str)
    print_colored(f"✅ Exporté vers {filename}", "green")

def format_timestamp(seconds):
    """Formate un timestamp en heures:minutes:secondes"""
    return datetime.fromtimestamp(seconds).strftime("%H:%M:%S")

def is_private_ip(ip_str):
    """Vérifie si une IP est privée (RFC 1918)"""
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private
    except ValueError:
        return False