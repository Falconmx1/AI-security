#!/usr/bin/env python3
"""
Security AI - Main Entry Point
Tortuga Power 🐢🔥
"""

import sys
import argparse
from modules.scanner import VulnerabilityScanner
from modules.malware_detector import MalwareDetector
from modules.ids import IntrusionDetectionSystem
from modules.responder import ThreatResponder

def show_banner():
    banner = """
    🐢🐢🐢🐢🐢🐢🐢🐢🐢🐢🐢🐢🐢🐢🐢🐢🐢🐢🐢🐢🐢🐢🐢🐢🐢🐢🐢
    🐢                                                  🐢
    🐢           SECURITY AI - TORTUGA POWER           🐢
    🐢          Herramienta de Ciberseguridad IA       🐢
    🐢              Sin Ollama, sin pedos              🐢
    🐢                                                  🐢
    🐢🐢🐢🐢🐢🐢🐢🐢🐢🐢🐢🐢🐢🐢🐢🐢🐢🐢🐢🐢🐢🐢🐢🐢🐢🐢🐢
    """
    print(banner)

def main():
    show_banner()
    
    parser = argparse.ArgumentParser(description='Security AI - Ciberseguridad con IA')
    parser.add_argument('-s', '--scan', help='Escanea una IP o dominio (ej: 192.168.1.1)')
    parser.add_argument('-m', '--malware', help='Analiza un archivo en busca de malware')
    parser.add_argument('-i', '--ids', action='store_true', help='Inicia el sistema de detección de intrusos')
    parser.add_argument('-r', '--responder', action='store_true', help='Activa el respondedor automático')
    
    args = parser.parse_args()
    
    if args.scan:
        scanner = VulnerabilityScanner()
        scanner.scan_target(args.scan)
    elif args.malware:
        detector = MalwareDetector()
        result = detector.analyze_file(args.malware)
        if result['is_malware']:
            print(f"⚠️  ¡MALWARE DETECTADO! Tipo: {result['type']}")
            responder = ThreatResponder()
            responder.quarantine_file(args.malware)
        else:
            print("✅ Archivo limpio")
    elif args.ids:
        ids = IntrusionDetectionSystem()
        ids.start_monitoring()
    elif args.responder:
        responder = ThreatResponder()
        responder.activate_autoresponder()
    else:
        print("Uso: python main.py [--scan IP] [--malware archivo] [--ids] [--responder]")

if __name__ == "__main__":
    main()
