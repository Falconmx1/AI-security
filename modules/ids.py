import threading
import time
import json
import subprocess
import re
from datetime import datetime
from collections import defaultdict, deque

class IntrusionDetectionSystem:
    def __init__(self):
        self.suspicious_ips = defaultdict(int)
        self.failed_logins = defaultdict(list)
        self.connection_history = deque(maxlen=1000)
        self.running = False
        self.threshold = 10  # Intentos fallidos antes de alertar
        
    def monitor_connections(self):
        """Monitorea conexiones de red usando netstat"""
        while self.running:
            try:
                # En Windows: netstat -n
                result = subprocess.run(['netstat', '-n'], capture_output=True, text=True, timeout=5)
                lines = result.stdout.split('\n')
                
                for line in lines:
                    if 'ESTABLISHED' in line or 'SYN_SENT' in line:
                        # Extraer IPs
                        ips = re.findall(r'\d+\.\d+\.\d+\.\d+', line)
                        if len(ips) >= 2:
                            local_ip, remote_ip = ips[0], ips[1]
                            if not remote_ip.startswith(('127.', '192.168.', '10.', '172.16.')):
                                self.suspicious_ips[remote_ip] += 1
                                
                                if self.suspicious_ips[remote_ip] > self.threshold:
                                    self.alert_administrator(f"Tráfico anormal desde IP {remote_ip}", remote_ip)
                
                self.check_failed_logins()
                
            except subprocess.TimeoutExpired:
                pass
            except Exception as e:
                print(f"Error en monitorización: {e}")
            
            time.sleep(5)  # Revisar cada 5 segundos
    
    def check_failed_logins(self):
        """Verifica logs de autenticación en busca de múltiples fallos"""
        try:
            # Windows Security Log (simulado con evento 4625)
            result = subprocess.run(['wevtutil', 'qe', 'Security', '/c:50', '/rd:true', '/f:text', '/q:*[System[(EventID=4625)]]'], 
                                  capture_output=True, text=True, timeout=10)
            
            if result.stdout:
                # Procesar eventos 4625 (logon fallido)
                current_time = datetime.now()
                for line in result.stdout.split('\n'):
                    if 'Account For Which Logon Failed' in line or 'Account Name' in line:
                        # Extraer usuario (simplificado)
                        username = line.split(':')[-1].strip()
                        self.failed_logins[username].append(current_time)
                        
                        # Limpiar intentos viejos (> 5 minutos)
                        self.failed_logins[username] = [t for t in self.failed_logins[username] 
                                                      if (current_time - t).seconds < 300]
                        
                        if len(self.failed_logins[username]) >= 5:
                            self.alert_administrator(f"Múltiples fallos de login para usuario {username}", None)
                            self.failed_logins[username].clear()
                            
        except Exception as e:
            pass  # Si no hay logs de seguridad, continuar
    
    def monitor_ports(self):
        """Monitorea escaneos de puertos rápidos"""
        port_scan_threshold = defaultdict(int)
        last_reset = datetime.now()
        
        while self.running:
            try:
                # Simulación de detección de escaneo
                result = subprocess.run(['netstat', '-an'], capture_output=True, text=True, timeout=5)
                
                current_time = datetime.now()
                if (current_time - last_reset).seconds > 60:
                    port_scan_threshold.clear()
                    last_reset = current_time
                
                for line in result.stdout.split('\n'):
                    if 'SYN_SENT' in line or 'TIME_WAIT' in line:
                        ips = re.findall(r'\d+\.\d+\.\d+\.\d+', line)
                        if ips:
                            remote_ip = ips[-1]  # Última IP encontrada
                            if not remote_ip.startswith(('127.', '192.168.', '10.')):
                                port_scan_threshold[remote_ip] += 1
                                
                                if port_scan_threshold[remote_ip] > 20:  # Muchas conexiones en poco tiempo
                                    self.alert_administrator(f"Posible escaneo de puertos desde IP {remote_ip}", remote_ip)
                                    port_scan_threshold[remote_ip] = 0
                
            except Exception:
                pass
            time.sleep(3)
    
    def alert_administrator(self, message, ip):
        """Envía alertas al administrador"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        alert = f"[ALERTA] {timestamp} - {message}"
        print(f"\n⚠️  {alert}")
        
        # Guardar en archivo de logs
        with open('ids_alerts.log', 'a') as log:
            log.write(f"{alert}\n")
        
        if ip:
            # Prevenir IP (bloquear)
            self.block_ip(ip)
    
    def block_ip(self, ip):
        """Bloquea una IP maliciosa"""
        try:
            # Comando de bloqueo para Windows Firewall
            subprocess.run(f'netsh advfirewall firewall add rule name="Block_{ip}" dir=in action=block remoteip={ip}', 
                         shell=True, capture_output=True)
            print(f"🔒 IP {ip} bloqueada automáticamente")
        except Exception:
            pass
    
    def start_monitoring(self):
        """Inicia todos los servicios de monitoreo"""
        print("\n🛡️  Iniciando Sistema de Detección de Intrusos...")
        self.running = True
        
        threads = [
            threading.Thread(target=self.monitor_connections, daemon=True),
            threading.Thread(target=self.monitor_ports, daemon=True)
        ]
        
        for thread in threads:
            thread.start()
        
        print("✅ IDS activo. Monitoreando en tiempo real...")
        print("Presiona Ctrl+C para detener")
        
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.running = False
            print("\n⏹️  IDS detenido")

if __name__ == "__main__":
    ids = IntrusionDetectionSystem()
    ids.start_monitoring()
