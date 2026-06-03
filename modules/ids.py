#!/usr/bin/env python3
"""
Intrusion Detection System (IDS) - Security AI
Detección de intrusos en tiempo real con integración de red
Tortuga Power 🐢🔥
"""

import threading
import time
import json
import subprocess
import re
from collections import defaultdict, deque
from datetime import datetime

class IntrusionDetectionSystem:
    def __init__(self):
        self.suspicious_ips = defaultdict(int)
        self.failed_logins = defaultdict(list)
        self.connection_history = deque(maxlen=1000)
        self.running = False
        self.threshold = 10  # Intentos fallidos antes de alertar
        self.network_alerts = []
        self.critical_alert_count = 0
        self.alert_log_file = "ids_alerts.log"
        self.network_integration = None
        self.stats = {
            'start_time': None,
            'total_alerts': 0,
            'critical_alerts': 0,
            'ips_blocked': 0,
            'packets_analyzed': 0
        }
        
    def log_alert(self, message, severity='medium', ip=None, alert_type='system'):
        """Registra una alerta en el sistema"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        alert = {
            'timestamp': timestamp,
            'message': message,
            'severity': severity,
            'ip': ip,
            'type': alert_type
        }
        
        # Guardar en memoria
        self.network_alerts.append(alert)
        self.stats['total_alerts'] += 1
        
        if severity == 'critical':
            self.stats['critical_alerts'] += 1
            self.critical_alert_count += 1
        
        # Mostrar en consola
        severity_symbols = {
            'low': 'ℹ️',
            'medium': '⚠️',
            'high': '🚨',
            'critical': '💀'
        }
        symbol = severity_symbols.get(severity, '🔔')
        print(f"\n{symbol} [{severity.upper()}] {timestamp} - {message}")
        if ip:
            print(f"   📍 IP involucrada: {ip}")
        
        # Guardar en archivo
        try:
            with open(self.alert_log_file, 'a') as f:
                f.write(f"{json.dumps(alert)}\n")
        except Exception as e:
            print(f"Error escribiendo log: {e}")
        
        # Si es crítica, tomar acción inmediata
        if severity == 'critical' and ip:
            self.block_ip_auto(ip)
        
        return alert
    
    def block_ip_auto(self, ip):
        """Bloquea IP automáticamente en respuesta a alerta crítica"""
        try:
            if ip not in self.suspicious_ips:
                self.suspicious_ips[ip] = 0
            
            self.suspicious_ips[ip] += 1
            
            # Si ya ha sido reportada varias veces, bloquear
            if self.suspicious_ips[ip] >= 3:
                self.block_ip(ip)
                self.stats['ips_blocked'] += 1
        except Exception as e:
            print(f"Error bloqueando IP {ip}: {e}")
    
    def monitor_connections(self):
        """Monitorea conexiones de red usando netstat"""
        last_cleanup = time.time()
        
        while self.running:
            try:
                # Comando según el sistema operativo
                if os.name == 'nt':  # Windows
                    result = subprocess.run(['netstat', '-n'], capture_output=True, text=True, timeout=5)
                else:  # Linux/Mac
                    result = subprocess.run(['netstat', '-n', '-t', '-u'], capture_output=True, text=True, timeout=5)
                
                lines = result.stdout.split('\n')
                current_time = time.time()
                
                # Limpiar registros viejos cada minuto
                if current_time - last_cleanup > 60:
                    self.cleanup_old_records(current_time)
                    last_cleanup = current_time
                
                for line in lines:
                    # Detectar conexiones establecidas
                    if 'ESTABLISHED' in line or 'SYN_SENT' in line:
                        # Extraer IPs usando regex
                        ips = re.findall(r'\d+\.\d+\.\d+\.\d+', line)
                        if len(ips) >= 2:
                            local_ip, remote_ip = ips[0], ips[1]
                            
                            # Ignorar IPs locales y privadas
                            if not remote_ip.startswith(('127.', '192.168.', '10.', '172.16.', '169.254.')):
                                self.suspicious_ips[remote_ip] += 1
                                
                                # Alertar si hay muchas conexiones desde misma IP
                                if self.suspicious_ips[remote_ip] > self.threshold:
                                    self.log_alert(
                                        f"Tráfico anormal desde IP {remote_ip} ({self.suspicious_ips[remote_ip]} conexiones)",
                                        'high' if self.suspicious_ips[remote_ip] > self.threshold * 2 else 'medium',
                                        remote_ip,
                                        'network_anomaly'
                                    )
                                    # Reset counter after alert
                                    self.suspicious_ips[remote_ip] = 0
                    
                    # Detectar puertos en escucha sospechosos
                    if 'LISTENING' in line:
                        ports = re.findall(r':(\d+)\s', line)
                        for port in ports:
                            port_num = int(port)
                            suspicious_ports = [4444, 5555, 6667, 1337, 31337, 12345, 54321]
                            if port_num in suspicious_ports:
                                self.log_alert(
                                    f"Puerto sospechoso en escucha: {port_num}",
                                    'high',
                                    None,
                                    'port_listening'
                                )
                
                # Verificar logs de autenticación
                self.check_failed_logins()
                
            except subprocess.TimeoutExpired:
                pass
            except Exception as e:
                print(f"Error en monitorización de conexiones: {e}")
            
            time.sleep(5)  # Revisar cada 5 segundos
    
    def cleanup_old_records(self, current_time):
        """Limpia registros antiguos para evitar memoria infinita"""
        # Limpiar intentos de login viejos (> 5 minutos)
        for user in list(self.failed_logins.keys()):
            self.failed_logins[user] = [t for t in self.failed_logins[user] 
                                      if current_time - t < 300]
            if not self.failed_logins[user]:
                del self.failed_logins[user]
    
    def check_failed_logins(self):
        """Verifica logs de autenticación en busca de múltiples fallos"""
        try:
            if os.name == 'nt':  # Windows
                # Evento 4625 = Logon fallido
                result = subprocess.run(
                    ['wevtutil', 'qe', 'Security', '/c:50', '/rd:true', '/f:text', '/q:*[System[(EventID=4625)]]'],
                    capture_output=True, text=True, timeout=10
                )
                
                if result.stdout:
                    current_time = time.time()
                    lines = result.stdout.split('\n')
                    
                    for i, line in enumerate(lines):
                        if 'Account Name:' in line and i > 0:
                            # Extraer nombre de usuario
                            username = line.split(':')[-1].strip()
                            if username and username != '-':
                                self.failed_logins[username].append(current_time)
                                
                                # Verificar si hay muchos fallos recientes
                                recent_failures = [t for t in self.failed_logins[username] 
                                                if current_time - t < 300]
                                
                                if len(recent_failures) >= 5:
                                    self.log_alert(
                                        f"Múltiples fallos de autenticación para usuario '{username}' ({len(recent_failures)} en 5 minutos)",
                                        'high',
                                        None,
                                        'bruteforce'
                                    )
                                    # Limpiar después de alertar
                                    self.failed_logins[username] = []
            
            else:  # Linux - revisar /var/log/auth.log
                result = subprocess.run(
                    ['tail', '-n', '100', '/var/log/auth.log'],
                    capture_output=True, text=True, timeout=5
                )
                
                if result.stdout:
                    current_time = time.time()
                    failed_pattern = re.compile(r'Failed password for (\S+) from (\d+\.\d+\.\d+\.\d+)')
                    
                    for line in result.stdout.split('\n'):
                        match = failed_pattern.search(line)
                        if match:
                            username, ip = match.groups()
                            key = f"{username}_{ip}"
                            if key not in self.failed_logins:
                                self.failed_logins[key] = []
                            self.failed_logins[key].append(current_time)
                            
                            # Limpiar viejos
                            self.failed_logins[key] = [t for t in self.failed_logins[key] 
                                                    if current_time - t < 300]
                            
                            if len(self.failed_logins[key]) >= 5:
                                self.log_alert(
                                    f"Posible ataque de fuerza bruta a '{username}' desde {ip}",
                                    'high',
                                    ip,
                                    'bruteforce'
                                )
                                self.failed_logins[key] = []
                                
        except Exception as e:
            pass  # Silenciar errores de logs
    
    def monitor_ports(self):
        """Monitorea escaneos de puertos rápidos"""
        port_scan_threshold = defaultdict(int)
        port_scan_ips = defaultdict(set)
        last_reset = datetime.now()
        
        while self.running:
            try:
                # Comando según OS
                if os.name == 'nt':
                    result = subprocess.run(['netstat', '-an'], capture_output=True, text=True, timeout=5)
                else:
                    result = subprocess.run(['netstat', '-an', '-t'], capture_output=True, text=True, timeout=5)
                
                current_time = datetime.now()
                
                # Resetear contadores cada minuto
                if (current_time - last_reset).seconds > 60:
                    port_scan_threshold.clear()
                    port_scan_ips.clear()
                    last_reset = current_time
                
                for line in result.stdout.split('\n'):
                    # Buscar conexiones SYN_SENT (escaneo activo) o TIME_WAIT
                    if 'SYN_SENT' in line or 'TIME_WAIT' in line:
                        ips = re.findall(r'\d+\.\d+\.\d+\.\d+', line)
                        if ips:
                            remote_ip = ips[-1]  # Última IP (remota)
                            
                            # Ignorar IPs locales
                            if not remote_ip.startswith(('127.', '192.168.', '10.', '172.16.', '169.254.')):
                                port_scan_threshold[remote_ip] += 1
                                
                                # Extraer puerto si es posible
                                port_match = re.search(r':(\d+)\s', line)
                                if port_match:
                                    port_scan_ips[remote_ip].add(int(port_match.group(1)))
                                
                                # Detectar escaneo rápido (muchas conexiones en poco tiempo)
                                if port_scan_threshold[remote_ip] > 30:
                                    unique_ports = len(port_scan_ips[remote_ip])
                                    self.log_alert(
                                        f"Posible escaneo de puertos desde IP {remote_ip} - {port_scan_threshold[remote_ip]} conexiones, {unique_ports} puertos únicos",
                                        'high' if unique_ports > 20 else 'medium',
                                        remote_ip,
                                        'port_scan'
                                    )
                                    port_scan_threshold[remote_ip] = 0
                
            except Exception as e:
                pass
            time.sleep(3)
    
    def alert_administrator(self, message, ip=None):
        """Método legacy para compatibilidad"""
        self.log_alert(message, 'high', ip, 'admin_alert')
    
    def block_ip(self, ip):
        """Bloquea una IP maliciosa en el firewall"""
        try:
            rule_name = f"SecurityAI_Block_{ip.replace('.', '_')}"
            
            if os.name == 'nt':  # Windows
                # Verificar si la regla ya existe
                check = subprocess.run(
                    f'netsh advfirewall firewall show rule name="{rule_name}"',
                    shell=True, capture_output=True, text=True
                )
                
                if 'No rules match' in check.stdout:
                    cmd = f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block remoteip={ip}'
                    subprocess.run(cmd, shell=True, capture_output=True)
                    self.log_alert(f"IP {ip} bloqueada en firewall", 'medium', ip, 'auto_block')
                    print(f"🔒 IP {ip} bloqueada automáticamente")
                else:
                    print(f"ℹ️ IP {ip} ya estaba bloqueada")
                    
            else:  # Linux
                # Verificar si ya existe la regla
                check = subprocess.run(f'sudo iptables -C INPUT -s {ip} -j DROP', shell=True, capture_output=True)
                if check.returncode != 0:
                    subprocess.run(f'sudo iptables -A INPUT -s {ip} -j DROP', shell=True)
                    self.log_alert(f"IP {ip} bloqueada en iptables", 'medium', ip, 'auto_block')
                    print(f"🔒 IP {ip} bloqueada automáticamente")
                    
        except Exception as e:
            print(f"❌ Error al bloquear IP {ip}: {e}")
    
    def receive_alert(self, alert_data):
        """Recibe alertas del Network Analyzer u otros módulos"""
        message = alert_data.get('message', 'Alerta de red')
        severity = alert_data.get('severity', 'medium')
        ip = alert_data.get('ip')
        
        self.log_alert(
            f"[Network] {message}",
            severity,
            ip,
            'network_integration'
        )
        
        # Si la alerta es crítica y tenemos IP, tomar acción
        if severity == 'critical' and ip:
            self.block_ip_auto(ip)
    
    def integrate_network_analyzer(self, responder=None):
        """Integra el analizador de red con el IDS"""
        try:
            from modules.network_analyzer import NetworkIDSIntegration
            
            print("🌐 Conectando Network Analyzer al IDS...")
            
            # Si no se proporcionó responder, crear uno nuevo
            if responder is None:
                from modules.responder import ThreatResponder
                responder = ThreatResponder()
            
            self.network_integration = NetworkIDSIntegration(self, responder)
            self.log_alert("Network Analyzer integrado exitosamente", 'low', None, 'integration')
            return self.network_integration
            
        except ImportError as e:
            print(f"⚠️ No se pudo integrar Network Analyzer: {e}")
            return None
        except Exception as e:
            print(f"❌ Error integrando Network Analyzer: {e}")
            return None
    
    def start_monitoring(self):
        """Inicia todos los servicios de monitoreo"""
        print("\n🛡️  Iniciando Sistema de Detección de Intrusos...")
        self.running = True
        self.stats['start_time'] = datetime.now()
        
        # Crear y iniciar threads
        threads = [
            threading.Thread(target=self.monitor_connections, name="IDS-Connections", daemon=True),
            threading.Thread(target=self.monitor_ports, name="IDS-Ports", daemon=True)
        ]
        
        for thread in threads:
            thread.start()
        
        print("✅ IDS activo. Monitoreando en tiempo real...")
        print(f"📊 Log de alertas: {self.alert_log_file}")
        print("💡 Presiona Ctrl+C para detener\n")
        
        # Mostrar estadísticas periódicamente
        last_stats_time = time.time()
        
        try:
            while self.running:
                time.sleep(1)
                
                # Mostrar estadísticas cada 30 segundos
                current_time = time.time()
                if current_time - last_stats_time > 30:
                    self.show_stats()
                    last_stats_time = current_time
                    
        except KeyboardInterrupt:
            self.stop_monitoring()
    
    def show_stats(self):
        """Muestra estadísticas del IDS"""
        if self.stats['start_time']:
            uptime = datetime.now() - self.stats['start_time']
            hours = uptime.total_seconds() / 3600
            
            print(f"\n📊 [IDS Stats] Uptime: {hours:.1f}h | Alertas: {self.stats['total_alerts']} "
                  f"(Críticas: {self.stats['critical_alerts']}) | IPs bloqueadas: {self.stats['ips_blocked']}")
    
    def stop_monitoring(self):
        """Detiene el monitoreo del IDS"""
        self.running = False
        print("\n⏹️  IDS detenido")
        
        # Guardar resumen final
        summary = {
            'stop_time': datetime.now().isoformat(),
            'stats': self.stats,
            'last_alerts': self.network_alerts[-5:] if self.network_alerts else []
        }
        
        try:
            with open('ids_summary.json', 'w') as f:
                json.dump(summary, f, indent=2)
            print(f"📄 Resumen guardado en ids_summary.json")
        except Exception as e:
            print(f"Error guardando resumen: {e}")
    
    def get_alerts(self, severity=None, limit=50):
        """Obtiene alertas filtradas"""
        alerts = self.network_alerts
        if severity:
            alerts = [a for a in alerts if a['severity'] == severity]
        return alerts[-limit:]

# Para pruebas independientes
if __name__ == "__main__":
    import os
    
    print("🐢 Security AI - IDS Test Mode")
    ids = IntrusionDetectionSystem()
    
    print("\nOpciones:")
    print("1. Iniciar monitoreo normal")
    print("2. Probar con integración de Network Analyzer")
    print("3. Simular alerta")
    
    option = input("\nSelecciona: ")
    
    if option == "1":
        ids.start_monitoring()
    elif option == "2":
        network_ids = ids.integrate_network_analyzer()
        if network_ids:
            print("✅ Integración completada. Iniciando monitoreo...")
            ids.start_monitoring()
        else:
            print("❌ No se pudo integrar")
    elif option == "3":
        ids.log_alert("ALERTA DE PRUEBA", "high", "192.168.1.100", "test")
        print("✅ Alerta de prueba generada")
