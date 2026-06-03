#!/usr/bin/env python3
"""
Behavior Analyzer - Cryptojacking & Ransomware Detection
Análisis de comportamiento en tiempo real para amenazas avanzadas
Tortuga Power 🐢🔥
"""

import psutil
import hashlib
import os
import json
import threading
import time
from collections import defaultdict, deque
from datetime import datetime
import re

class BehaviorAnalyzer:
    """Analiza comportamiento del sistema para detectar cryptojacking y ransomware"""
    
    def __init__(self):
        self.cpu_history = deque(maxlen=60)  # Últimos 60 segundos
        self.process_history = defaultdict(lambda: {'cpu': deque(maxlen=30), 'memory': deque(maxlen=30)})
        self.file_operations = deque(maxlen=1000)
        self.suspicious_processes = []
        self.running = False
        self.alert_callbacks = []
        
        # Patrones de cryptojacking
        self.crypto_mining_patterns = [
            'minerd', 'xmrig', 'cgminer', 'bfgminer', 'cpuminer', 'ethminer',
            'minergate', 'nicehash', 'claymore', 'phoenixminer', 'lolminer',
            't-rex', 'nbminer', 'gminer', 'teamredminer', 'srbmul'
        ]
        
        # Patrones de ransomware
        self.ransomware_extensions = [
            '.encrypted', '.locked', '.crypt', '.ransom', '.wannacry', '.cerber',
            '.locky', '.crypto', '.zepto', '.odcodc', '.wallet', '.aesir',
            '.dharma', '.arena', '.bip', '.lol', '.mogodb', '.ontario'
        ]
        
        # Extensiones críticas que suelen ser víctimas de ransomware
        self.critical_extensions = [
            '.doc', '.docx', '.xls', '.xlsx', '.pdf', '.jpg', '.png', '.ppt', '.pptx',
            '.zip', '.rar', '.7z', '.txt', '.sql', '.db', '.psd', '.ai', '.cdr'
        ]
        
        self.ransomware_processes = [
            'taskkill', 'vssadmin', 'bcdedit', 'wmic', 'cipher', 'wevtutil',
            'schtasks', 'reg.exe', 'net.exe', 'attrib', 'icacls'
        ]
        
        self.load_config()
    
    def load_config(self):
        """Carga configuración desde archivo JSON"""
        try:
            with open('data/behavior_config.json', 'r') as f:
                config = json.load(f)
                self.crypto_mining_patterns.extend(config.get('crypto_mining', []))
                self.ransomware_processes.extend(config.get('ransomware_commands', []))
                self.ransomware_extensions.extend(config.get('ransomware_extensions', []))
        except FileNotFoundError:
            pass
    
    def register_alert_callback(self, callback):
        """Registra función para alertas"""
        self.alert_callbacks.append(callback)
    
    def send_alert(self, message, severity='high', process=None, details=None):
        """Envía alerta a todos los callbacks"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        alert = {
            'timestamp': timestamp,
            'message': message,
            'severity': severity,
            'type': 'behavior_analysis',
            'process': process,
            'details': details or {}
        }
        
        print(f"\n🎯 [{severity.upper()}] BEHAVIOR ANALYZER: {message}")
        if process:
            print(f"   Proceso: {process}")
        
        # Guardar en archivo
        with open('behavior_alerts.log', 'a') as f:
            f.write(f"{json.dumps(alert)}\n")
        
        # Notificar callbacks
        for callback in self.alert_callbacks:
            try:
                callback(alert)
            except Exception as e:
                print(f"Error en callback: {e}")
        
        return alert
    
    def detect_cryptojacking(self, process):
        """Detecta minería de criptomonedas por comportamiento"""
        try:
            proc = psutil.Process(process.pid)
            cpu_percent = proc.cpu_percent(interval=0.5)
            memory_percent = proc.memory_percent()
            
            # Guardar historial
            self.process_history[proc.name()]['cpu'].append(cpu_percent)
            self.process_history[proc.name()]['memory'].append(memory_percent)
            
            # Calcular promedios
            avg_cpu = sum(self.process_history[proc.name()]['cpu']) / max(1, len(self.process_history[proc.name()]['cpu']))
            avg_memory = sum(self.process_history[proc.name()]['memory']) / max(1, len(self.process_history[proc.name()]['memory']))
            
            # Verificar por nombre conocido de minero
            process_name_lower = proc.name().lower()
            for pattern in self.crypto_mining_patterns:
                if pattern in process_name_lower:
                    self.send_alert(
                        f"🔨 PROCESO DE MINERÍA DETECTADO: {proc.name()}",
                        'critical',
                        proc.name(),
                        {'pattern': pattern, 'cpu': f"{cpu_percent:.1f}%", 'memory': f"{memory_percent:.1f}%"}
                    )
                    return True
            
            # Comportamiento sospechoso: alto uso de CPU por mucho tiempo
            if len(self.process_history[proc.name()]['cpu']) > 10:
                if avg_cpu > 70 and cpu_percent > 80:
                    # Verificar conexiones de red a pools conocidos
                    connections = self.get_network_connections(proc.pid)
                    mining_ports = [3333, 4444, 5555, 7777, 8888, 14444, 18888, 19999]
                    
                    for conn in connections:
                        if conn['port'] in mining_ports:
                            self.send_alert(
                                f"⛏️ CRYPTOJACKING DETECTADO: {proc.name()} usando {cpu_percent:.1f}% CPU conectado a puerto {conn['port']}",
                                'critical',
                                proc.name(),
                                {'cpu_avg': f"{avg_cpu:.1f}%", 'remote_port': conn['port'], 'remote_ip': conn['ip']}
                            )
                            return True
            
            # Picos repentinos de CPU
            cpu_history = list(self.process_history[proc.name()]['cpu'])
            if len(cpu_history) > 5:
                recent_avg = sum(cpu_history[-3:]) / 3
                older_avg = sum(cpu_history[:3]) / 3
                if recent_avg > older_avg * 3 and recent_avg > 60:
                    self.send_alert(
                        f"⚠️ PICOS ANORMALES DE CPU en {proc.name()}: {recent_avg:.1f}% (anterior {older_avg:.1f}%)",
                        'medium',
                        proc.name(),
                        {'current_avg': f"{recent_avg:.1f}%", 'previous_avg': f"{older_avg:.1f}%"}
                    )
                    return True
                    
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        return False
    
    def get_network_connections(self, pid):
        """Obtiene conexiones de red de un proceso"""
        connections = []
        try:
            proc = psutil.Process(pid)
            for conn in proc.connections():
                if conn.raddr:
                    connections.append({
                        'ip': conn.raddr.ip,
                        'port': conn.raddr.port
                    })
        except Exception:
            pass
        return connections
    
    def detect_ransomware_behavior(self, process, file_events=None):
        """Detecta ransomware por comportamiento típico"""
        try:
            proc = psutil.Process(process.pid)
            proc_name = proc.name().lower()
            
            # Detectar comandos típicos de ransomware
            cmdline = ' '.join(proc.cmdline()).lower() if proc.cmdline() else ''
            
            for pattern in self.ransomware_processes:
                if pattern in cmdline:
                    # Verificar si está eliminando shadows o modificando archivos
                    if 'delete shadows' in cmdline or 'vssadmin' in cmdline:
                        self.send_alert(
                            f"💀 RANSOMWARE DETECTADO: Eliminando shadow copies - {proc.name()}",
                            'critical',
                            proc.name(),
                            {'command': cmdline[:200]}
                        )
                        return True
                    
                    if 'cipher' in cmdline and '/e' in cmdline:
                        self.send_alert(
                            f"🔐 RANSOMWARE DETECTADO: Encriptando archivos - {proc.name()}",
                            'critical',
                            proc.name(),
                            {'command': cmdline[:200]}
                        )
                        return True
            
            # Detectar renombrado masivo de archivos
            if file_events:
                rename_events = [e for e in file_events if e.get('type') == 'rename']
                if len(rename_events) > 20:
                    # Verificar extensiones sospechosas
                    for event in rename_events:
                        new_name = event.get('new_name', '')
                        for ext in self.ransomware_extensions:
                            if new_name.endswith(ext):
                                self.send_alert(
                                    f"🔒 RANSOMWARE: Archivos siendo renombrados con extensión {ext}",
                                    'critical',
                                    proc_name,
                                    {'sample': new_name, 'count': len(rename_events)}
                                )
                                return True
            
            # Alto uso de CPU + E/S de disco (encriptación)
            cpu = proc.cpu_percent(interval=0.3)
            io_counters = proc.io_counters() if hasattr(proc, 'io_counters') else None
            
            if cpu > 60 and io_counters:
                write_bytes = io_counters.write_bytes
                if write_bytes > 50 * 1024 * 1024:  # 50MB escritos
                    self.send_alert(
                        f"⚠️ POSIBLE RANSOMWARE: {proc_name} escribiendo {write_bytes/1024/1024:.1f}MB + CPU {cpu:.1f}%",
                        'high',
                        proc_name,
                        {'written_mb': f"{write_bytes/1024/1024:.1f}", 'cpu': f"{cpu:.1f}%"}
                    )
                    return True
                    
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        return False
    
    def monitor_system(self):
        """Monitoreo continuo del sistema"""
        last_file_scan = time.time()
        monitored_processes = set()
        
        while self.running:
            try:
                current_time = time.time()
                
                # Escanear procesos cada 2 segundos
                for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                    try:
                        # Detectar cryptojacking
                        self.detect_cryptojacking(proc)
                        
                        # Detectar ransomware (cada 5 segundos por proceso)
                        if proc.pid not in monitored_processes or current_time - last_file_scan > 5:
                            self.detect_ransomware_behavior(proc)
                            monitored_processes.add(proc.pid)
                            
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                
                # Escanear sistema de archivos cada 10 segundos (búsqueda de extensiones ransomware)
                if current_time - last_file_scan > 10:
                    self.scan_for_ransomware_files()
                    last_file_scan = current_time
                
                time.sleep(2)
                
            except Exception as e:
                print(f"Error en monitorización: {e}")
                time.sleep(5)
    
    def scan_for_ransomware_files(self):
        """Escanea directorios comunes en busca de archivos con extensiones ransomware"""
        common_dirs = [
            os.path.expanduser("~/Desktop"),
            os.path.expanduser("~/Documents"),
            os.path.expanduser("~/Downloads"),
            os.path.expanduser("~/Pictures")
        ]
        
        ransomware_files_found = []
        
        for directory in common_dirs:
            if not os.path.exists(directory):
                continue
            
            try:
                for root, dirs, files in os.walk(directory):
                    for file in files:
                        for ext in self.ransomware_extensions:
                            if file.lower().endswith(ext):
                                file_path = os.path.join(root, file)
                                mod_time = os.path.getmtime(file_path)
                                if time.time() - mod_time < 300:  # Modificado en últimos 5 minutos
                                    ransomware_files_found.append(file_path)
                                    
                    # Limitar profundidad
                    if len(ransomware_files_found) > 10:
                        break
                        
            except (PermissionError, OSError):
                continue
        
        if ransomware_files_found:
            self.send_alert(
                f"🔴 POSIBLE INFECCIÓN RANSOMWARE: {len(ransomware_files_found)} archivos con extensiones sospechosas",
                'critical',
                None,
                {'files': ransomware_files_found[:5]}
            )
            return True
        
        return False
    
    def start_monitoring(self):
        """Inicia el monitoreo de comportamiento"""
        print("\n🧠 Iniciando Behavior Analyzer (Cryptojacking + Ransomware)")
        print("=" * 60)
        print("📊 Monitoreando:")
        print("  - Uso de CPU/Memoria por proceso")
        print("  - Patrones de cryptomining")
        print("  - Comportamiento ransomware")
        print("  - Extensiones de archivo sospechosas")
        print("=" * 60)
        
        self.running = True
        
        monitor_thread = threading.Thread(target=self.monitor_system, daemon=True)
        monitor_thread.start()
        
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop_monitoring()
    
    def stop_monitoring(self):
        """Detiene el monitoreo"""
        self.running = False
        print("\n⏹️ Behavior Analyzer detenido")

# Integración con el sistema existente
class BehaviorIntegration:
    """Integra Behavior Analyzer con IDS y Responder"""
    
    def __init__(self, ids_system, responder_system):
        self.ids = ids_system
        self.responder = responder_system
        self.analyzer = BehaviorAnalyzer()
        
        # Registrar callback
        self.analyzer.register_alert_callback(self.handle_behavior_alert)
    
    def handle_behavior_alert(self, alert_data):
        """Maneja alertas del behavior analyzer"""
        print(f"\n🔗 [BehaviorIntegration] Alerta recibida: {alert_data['message']}")
        
        # Enviar al IDS
        if self.ids:
            self.ids.receive_alert(alert_data)
        
        # Acción automática según severidad
        if alert_data['severity'] == 'critical':
            # Matar proceso si está identificado
            if alert_data.get('process'):
                print(f"🛑 Terminando proceso malicioso: {alert_data['process']}")
                if self.responder:
                    self.responder.kill_process(alert_data['process'])
            
            # Aislar el sistema si es ransomware
            if 'RANSOMWARE' in alert_data['message'].upper():
                self.isolate_system()
    
    def isolate_system(self):
        """Aísla el sistema de la red en caso de ransomware"""
        print("🚨 ¡RANSOMWARE DETECTADO! Aislando sistema...")
        
        try:
            import subprocess
            if os.name == 'nt':  # Windows
                subprocess.run('netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound', shell=True)
                print("🔒 Firewall bloqueado - Sistema aislado")
            else:  # Linux
                subprocess.run('sudo ufw default deny incoming', shell=True)
                subprocess.run('sudo ufw default deny outgoing', shell=True)
                print("🔒 UFW bloqueado - Sistema aislado")
        except Exception as e:
            print(f"Error aislando sistema: {e}")
    
    def start(self):
        """Inicia el behavior analyzer integrado"""
        print("🐢🔬 Security AI - Behavior Analyzer Integrado")
        print("Detección de Cryptojacking y Ransomware ACTIVADA")
        self.analyzer.start_monitoring()

if __name__ == "__main__":
    print("🧪 Behavior Analyzer - Modo de prueba")
    analyzer = BehaviorAnalyzer()
    analyzer.start_monitoring()
