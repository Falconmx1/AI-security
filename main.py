#!/usr/bin/env python3
"""
Security AI - Main Entry Point
Tortuga Power 🐢🔥
Herramienta de ciberseguridad con IA integrada
"""

import sys
import argparse
import threading
import time
from datetime import datetime

# Importar todos los módulos
from modules.scanner import VulnerabilityScanner
from modules.malware_detector import MalwareDetector
from modules.ids import IntrusionDetectionSystem
from modules.responder import ThreatResponder
from modules.network_analyzer import NetworkTrafficAnalyzer, NetworkIDSIntegration

def show_banner():
    banner = """
    🐢🐢🐢🐢🐢🐢🐢🐢🐢🐢🐢🐢🐢🐢🐢🐢🐢🐢🐢🐢🐢🐢🐢🐢🐢🐢🐢
    🐢                                                  🐢
    🐢           SECURITY AI - TORTUGA POWER           🐢
    🐢          Herramienta de Ciberseguridad IA       🐢
    🐢              Sin Ollama, sin pedos              🐢
    🐢        Análisis de red, malware, IDS y más      🐢
    🐢                                                  🐢
    🐢🐢🐢🐢🐢🐢🐢🐢🐢🐢🐢🐢🐢🐢🐢🐢🐢🐢🐢🐢🐢🐢🐢🐢🐢🐢🐢
    """
    print(banner)
    print("\n🐢 Security AI - Protección con caparazón duro")
    print(f"📅 Iniciado: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

class SecurityAI:
    """Clase principal que orquesta todos los módulos"""
    
    def __init__(self):
        self.scanner = None
        self.detector = None
        self.ids = None
        self.responder = None
        self.network_analyzer = None
        self.network_integration = None
        self.running_modules = []
    
    def init_scanner(self):
        """Inicializa el escáner de vulnerabilidades"""
        self.scanner = VulnerabilityScanner()
        print("✅ Escáner de vulnerabilidades listo")
    
    def init_malware_detector(self):
        """Inicializa el detector de malware"""
        self.detector = MalwareDetector()
        print("✅ Detector de malware listo")
    
    def init_ids(self):
        """Inicializa el sistema de detección de intrusos"""
        self.ids = IntrusionDetectionSystem()
        print("✅ IDS listo")
    
    def init_responder(self):
        """Inicializa el respondedor automático"""
        self.responder = ThreatResponder()
        print("✅ Respondedor automático listo")
    
    def init_network_analyzer(self, interface=None):
        """Inicializa el analizador de red"""
        if self.ids and self.responder:
            self.network_integration = NetworkIDSIntegration(self.ids, self.responder)
            print("✅ Network Analyzer integrado con IDS y Responder")
            return self.network_integration
        else:
            self.network_analyzer = NetworkTrafficAnalyzer()
            print("✅ Network Analyzer standalone listo")
            return self.network_analyzer
    
    def run_scan(self, target):
        """Ejecuta escaneo de vulnerabilidades"""
        if not self.scanner:
            self.init_scanner()
        self.scanner.scan_target(target)
    
    def run_malware_check(self, file_path):
        """Ejecuta análisis de malware"""
        if not self.detector:
            self.init_malware_detector()
        
        result = self.detector.analyze_file(file_path)
        
        print(f"\n{'='*50}")
        print(f"🎯 RESULTADO DEL ANÁLISIS:")
        print(f"Archivo: {result['file']}")
        print(f"Estado: {'⚠️ MALWARE' if result['is_malware'] else '✅ LIMPIO'}")
        print(f"Tipo: {result['type']}")
        print(f"Puntaje de riesgo: {result['score']}/100")
        
        if result['details']:
            print(f"Detalles:")
            for detail in result['details']:
                print(f"  - {detail}")
        
        # Si es malware, ofrecer cuarentena
        if result['is_malware']:
            if not self.responder:
                self.init_responder()
            
            print(f"\n⚠️ SE HA DETECTADO MALWARE!")
            respuesta = input("¿Mover a cuarentena? (s/n): ")
            if respuesta.lower() == 's':
                self.responder.quarantine_file(file_path)
        
        return result
    
    def run_ids(self):
        """Ejecuta el IDS en un hilo separado"""
        if not self.ids:
            self.init_ids()
        
        print("\n🛡️ Iniciando IDS en segundo plano...")
        ids_thread = threading.Thread(target=self.ids.start_monitoring, daemon=True)
        ids_thread.start()
        self.running_modules.append(('IDS', ids_thread))
        print("✅ IDS ejecutándose en segundo plano")
    
    def run_network_analysis(self, interface=None, integrate_with_ids=True):
        """Ejecuta el análisis de red"""
        if integrate_with_ids and self.ids and self.responder:
            network_module = self.init_network_analyzer(interface)
            print("\n🌐 Iniciando análisis de red integrado...")
            
            if hasattr(network_module, 'start'):
                network_thread = threading.Thread(target=network_module.start, args=(interface,), daemon=True)
                network_thread.start()
                self.running_modules.append(('NetworkAnalyzer', network_thread))
            else:
                network_module.start_analysis(interface)
        else:
            if not self.network_analyzer:
                self.init_network_analyzer(interface)
            
            print("\n🌐 Iniciando análisis de red standalone...")
            network_thread = threading.Thread(target=self.network_analyzer.start_analysis, args=(interface,), daemon=True)
            network_thread.start()
            self.running_modules.append(('NetworkAnalyzer', network_thread))
    
    def run_responder(self):
        """Ejecuta el respondedor automático"""
        if not self.responder:
            self.init_responder()
        
        print("\n🤖 Iniciando respondedor automático...")
        responder_thread = threading.Thread(target=self.responder.activate_autoresponder, daemon=True)
        responder_thread.start()
        self.running_modules.append(('Responder', responder_thread))
        print("✅ Respondedor automático activo")
    
    def show_status(self):
        """Muestra el estado de todos los módulos"""
        print("\n📊 ESTADO DE MÓDULOS:")
        print("-" * 40)
        print(f"🔍 Escáner: {'✅ Activo' if self.scanner else '❌ Inactivo'}")
        print(f"🦠 Malware Detector: {'✅ Activo' if self.detector else '❌ Inactivo'}")
        print(f"🛡️ IDS: {'✅ Activo' if self.ids else '❌ Inactivo'}")
        print(f"🤖 Responder: {'✅ Activo' if self.responder else '❌ Inactivo'}")
        print(f"🌐 Network Analyzer: {'✅ Activo' if (self.network_analyzer or self.network_integration) else '❌ Inactivo'}")
        print(f"📡 Módulos en ejecución: {len(self.running_modules)}")
    
    def stop_all(self):
        """Detiene todos los módulos en ejecución"""
        print("\n🛑 Deteniendo todos los módulos...")
        for name, thread in self.running_modules:
            print(f"  Deteniendo {name}...")
        self.running_modules.clear()
        print("✅ Todos los módulos detenidos")

def main():
    show_banner()
    
    parser = argparse.ArgumentParser(
        description='Security AI - Herramienta de Ciberseguridad con IA',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
EJEMPLOS DE USO:
  python main.py --scan 192.168.1.1              # Escanear IP
  python main.py --malware virus.exe             # Analizar malware
  python main.py --ids                           # Iniciar IDS
  python main.py --network                       # Analizar tráfico de red
  python main.py --ids --network --responder     # Modo completo (recomendado)
  python main.py --all                           # Activar todos los módulos
        """
    )
    
    # Módulos individuales
    parser.add_argument('-s', '--scan', metavar='IP', help='Escanea una IP o dominio')
    parser.add_argument('-m', '--malware', metavar='ARCHIVO', help='Analiza un archivo en busca de malware')
    parser.add_argument('--ids', action='store_true', help='Inicia el sistema de detección de intrusos')
    parser.add_argument('-n', '--network', action='store_true', help='Análisis de tráfico de red en tiempo real')
    parser.add_argument('-r', '--responder', action='store_true', help='Activa el respondedor automático')
    parser.add_argument('-a', '--all', action='store_true', help='Activa todos los módulos (IDS + Network + Responder)')
    
    # Opciones adicionales
    parser.add_argument('-i', '--interface', help='Interfaz de red para capturar (ej: eth0, wlan0)')
    parser.add_argument('--no-integrate', action='store_true', help='No integrar Network Analyzer con IDS')
    parser.add_argument('--status', action='store_true', help='Muestra el estado de los módulos')
    
    args = parser.parse_args()
    
    # Crear instancia principal
    security = SecurityAI()
    
    try:
        # Modo todo en uno
        if args.all:
            print("\n🐢 ACTIVANDO MODO TORTUGA TOTAL 🐢")
            print("=" * 50)
            
            # Iniciar IDS
            security.run_ids()
            time.sleep(1)
            
            # Iniciar Responder
            security.run_responder()
            time.sleep(1)
            
            # Iniciar Network Analyzer
            security.run_network_analysis(args.interface, integrate_with_ids=not args.no_integrate)
            
            print("\n" + "="*50)
            print("✅ TODOS LOS MÓDULOS ACTIVOS")
            print("Presiona Ctrl+C para detener todos los servicios")
            print("="*50)
            
            # Mantener vivo
            while True:
                time.sleep(1)
                if args.status:
                    security.show_status()
                    args.status = False  # Solo mostrar una vez
        
        # Modos individuales
        elif args.scan:
            security.run_scan(args.scan)
        
        elif args.malware:
            security.run_malware_check(args.malware)
        
        elif args.ids:
            security.run_ids()
            print("\n🛡️ IDS ejecutándose. Presiona Ctrl+C para detener")
            while True:
                time.sleep(1)
        
        elif args.network:
            security.run_network_analysis(args.interface, integrate_with_ids=not args.no_integrate)
            print("\n🌐 Análisis de red activo. Presiona Ctrl+C para detener")
            while True:
                time.sleep(1)
        
        elif args.responder:
            security.run_responder()
            print("\n🤖 Respondedor activo. Presiona Ctrl+C para detener")
            while True:
                time.sleep(1)
        
        elif args.status:
            security.show_status()
        
        else:
            # Modo interactivo
            print("\n🎮 MODO INTERACTIVO")
            print("Selecciona una opción:")
            print("1. Escanear vulnerabilidades")
            print("2. Analizar archivo (malware)")
            print("3. Iniciar IDS")
            print("4. Iniciar análisis de red")
            print("5. Iniciar respondedor")
            print("6. MODO COMPLETO (todos los módulos)")
            print("7. Salir")
            
            option = input("\nOpción: ")
            
            if option == '1':
                target = input("IP o dominio a escanear: ")
                security.run_scan(target)
            elif option == '2':
                file_path = input("Ruta del archivo: ")
                security.run_malware_check(file_path)
            elif option == '3':
                security.run_ids()
                input("\nPresiona Enter para detener el IDS...")
            elif option == '4':
                interface = input("Interfaz de red (opcional, Enter para auto): ")
                security.run_network_analysis(interface if interface else None)
                input("\nPresiona Enter para detener...")
            elif option == '5':
                security.run_responder()
                input("\nPresiona Enter para detener...")
            elif option == '6':
                args.all = True
                args.ids = True
                args.network = True
                args.responder = True
                # Re-ejecutar con modo completo
                security.run_ids()
                time.sleep(1)
                security.run_responder()
                time.sleep(1)
                security.run_network_analysis(args.interface)
                while True:
                    time.sleep(1)
            else:
                print("👋 ¡Hasta luego, tortuga power!")
                sys.exit(0)
    
    except KeyboardInterrupt:
        print("\n\n🛑 Recibida señal de interrupción")
        security.stop_all()
        print("\n👋 Security AI detenido. ¡Gracias por usar Tortuga Power!")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Error: {e}")
        security.stop_all()
        sys.exit(1)

if __name__ == "__main__":
    main()
