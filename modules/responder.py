import os
import shutil
import json
import subprocess
import datetime
from pathlib import Path

class ThreatResponder:
    def __init__(self):
        self.quarantine_dir = Path.home() / '.security_ai_quarantine'
        self.log_file = Path('responder_log.json')
        self.create_quarantine()
    
    def create_quarantine(self):
        """Crea el directorio de cuarentena"""
        if not self.quarantine_dir.exists():
            self.quarantine_dir.mkdir(parents=True)
            print(f"📁 Directorio de cuarentena creado: {self.quarantine_dir}")
    
    def quarantine_file(self, file_path):
        """Mueve un archivo sospechoso a cuarentena"""
        try:
            source = Path(file_path)
            if not source.exists():
                print(f"❌ Archivo no encontrado: {file_path}")
                return False
            
            # Crear nombre único
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            dest_name = f"{source.name}_{timestamp}.quarantine"
            dest_path = self.quarantine_dir / dest_name
            
            # Mover archivo
            shutil.move(str(source), str(dest_path))
            
            # Registrar acción
            self.log_action('quarantine', file_path, str(dest_path))
            print(f"✅ Archivo movido a cuarentena: {dest_path}")
            return True
            
        except Exception as e:
            print(f"❌ Error al mover a cuarentena: {e}")
            return False
    
    def kill_process(self, process_name):
        """Termina un proceso sospechoso"""
        try:
            if os.name == 'nt':  # Windows
                subprocess.run(f'taskkill /F /IM {process_name}', shell=True, capture_output=True)
                print(f"🔪 Proceso {process_name} terminado")
            else:  # Linux/Mac
                subprocess.run(f'pkill -f {process_name}', shell=True, capture_output=True)
            
            self.log_action('kill_process', process_name, 'terminated')
            return True
        except Exception as e:
            print(f"❌ Error al terminar proceso: {e}")
            return False
    
    def block_ip_firewall(self, ip_address):
        """Bloquea una IP en el firewall"""
        try:
            if os.name == 'nt':  # Windows
                rule_name = f"SecurityAI_Block_{ip_address.replace('.', '_')}"
                cmd = f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block remoteip={ip_address}'
                subprocess.run(cmd, shell=True, capture_output=True)
                print(f"🚫 IP {ip_address} bloqueada en firewall")
            else:  # Linux (iptables)
                subprocess.run(f'sudo iptables -A INPUT -s {ip_address} -j DROP', shell=True)
                print(f"🚫 IP {ip_address} bloqueada con iptables")
            
            self.log_action('block_ip', ip_address, 'blocked')
            return True
        except Exception as e:
            print(f"❌ Error al bloquear IP: {e}")
            return False
    
    def log_action(self, action, target, result):
        """Registra todas las acciones del respondedor"""
        log_entry = {
            'timestamp': datetime.datetime.now().isoformat(),
            'action': action,
            'target': target,
            'result': result
        }
        
        # Cargar logs existentes
        logs = []
        if self.log_file.exists():
            with open(self.log_file, 'r') as f:
                logs = json.load(f)
        
        logs.append(log_entry)
        
        # Guardar logs actualizados
        with open(self.log_file, 'w') as f:
            json.dump(logs, f, indent=2)
    
    def activate_autoresponder(self):
        """Activa el respondedor automático en modo continuo"""
        print("\n🤖 Activando Respuesta Automática a Amenazas...")
        print("El sistema monitoreará y responderá automáticamente")
        print("Presiona Ctrl+C para detener")
        
        # Simular monitoreo continuo (en un caso real, se conectaría al IDS)
        try:
            import time
            while True:
                # Aquí se conectaría con el IDS para recibir alertas
                time.sleep(5)
                print("🔄 Sistema respondedor activo...", end='\r')
        except KeyboardInterrupt:
            print("\n⏹️  Respondedor desactivado")
    
    def show_logs(self):
        """Muestra el historial de acciones"""
        if not self.log_file.exists():
            print("No hay acciones registradas")
            return
        
        with open(self.log_file, 'r') as f:
            logs = json.load(f)
        
        print("\n📋 HISTORIAL DE RESPUESTAS:")
        print("-" * 60)
        for log in logs[-10:]:  # Mostrar últimos 10
            print(f"[{log['timestamp']}] {log['action'].upper()}: {log['target']} -> {log['result']}")

if __name__ == "__main__":
    responder = ThreatResponder()
    
    print("Security AI - Respondedor Automático")
    print("1. Mover archivo a cuarentena")
    print("2. Terminar proceso")
    print("3. Bloquear IP")
    print("4. Ver logs")
    
    option = input("Selecciona una opción: ")
    
    if option == "1":
        file_path = input("Ruta del archivo: ")
        responder.quarantine_file(file_path)
    elif option == "2":
        process = input("Nombre del proceso (ej: malware.exe): ")
        responder.kill_process(process)
    elif option == "3":
        ip = input("Dirección IP: ")
        responder.block_ip_firewall(ip)
    elif option == "4":
        responder.show_logs()
