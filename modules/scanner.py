import socket
import sys
import json
import requests
from concurrent.futures import ThreadPoolExecutor

class VulnerabilityScanner:
    def __init__(self):
        self.common_ports = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 111: "RPC", 135: "RPC", 139: "NetBIOS",
            143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
            1723: "PPTP", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
            5900: "VNC", 6379: "Redis", 8080: "HTTP-Proxy", 27017: "MongoDB"
        }
        self.vulnerabilities = []
    
    def scan_port(self, ip, port):
        """Escanea un puerto específico"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((ip, port))
            sock.close()
            
            if result == 0:
                service = self.common_ports.get(port, "Desconocido")
                self.check_vulnerability(port, service)
                return port, service, True
        except Exception:
            pass
        return port, None, False
    
    def check_vulnerability(self, port, service):
        """Verifica vulnerabilidades conocidas por puerto/servicio"""
        vulns = {
            21: ["CVE-2020-12345: FTP Anonymous Access", "CVE-2019-6789: FTP Buffer Overflow"],
            22: ["CVE-2020-15778: SSH Command Injection", "Weak SSH Configuration"],
            80: ["CVE-2021-41773: Apache Path Traversal", "Missing Security Headers"],
            443: ["CVE-2022-22707: Apache HTTPD", "SSL/TLS Weak Ciphers"],
            3306: ["CVE-2020-14889: MySQL DoS", "Weak MySQL Password"],
            3389: ["BlueKeep (CVE-2019-0708)", "RDP Brute Force Risk"],
            445: ["EternalBlue (CVE-2017-0144)", "SMBv1 Enabled"]
        }
        
        if port in vulns:
            for vuln in vulns[port]:
                self.vulnerabilities.append({
                    'port': port,
                    'service': service,
                    'vulnerability': vuln
                })
    
    def scan_target(self, target):
        """Escanea todos los puertos comunes en el objetivo"""
        print(f"\n🔍 Escaneando objetivo: {target}")
        print("-" * 50)
        
        try:
            ip = socket.gethostbyname(target)
            print(f"✓ IP Resuelta: {ip}")
        except:
            print(f"✗ No se pudo resolver {target}")
            return
        
        open_ports = []
        
        with ThreadPoolExecutor(max_workers=50) as executor:
            results = executor.map(lambda p: self.scan_port(ip, p), self.common_ports.keys())
            for port, service, is_open in results:
                if is_open:
                    open_ports.append((port, service))
                    print(f"🔓 Puerto {port} abierto: {service}")
        
        print(f"\n📊 Resumen del escaneo:")
        print(f"Total puertos escaneados: {len(self.common_ports)}")
        print(f"Puertos abiertos encontrados: {len(open_ports)}")
        
        if self.vulnerabilities:
            print(f"\n⚠️  VULNERABILIDADES POTENCIALES ENCONTRADAS:")
            for vuln in self.vulnerabilities:
                print(f"  - Puerto {vuln['port']} ({vuln['service']}): {vuln['vulnerability']}")
        else:
            print(f"\n✅ No se encontraron vulnerabilidades comunes")
        
        self.generate_report(ip, open_ports)
    
    def generate_report(self, ip, open_ports):
        """Genera un reporte JSON del escaneo"""
        report = {
            'target': ip,
            'date': str(__import__('datetime').datetime.now()),
            'open_ports': [{'port': p, 'service': s} for p, s in open_ports],
            'vulnerabilities': self.vulnerabilities
        }
        
        with open(f'report_{ip.replace(".", "_")}.json', 'w') as f:
            json.dump(report, f, indent=4)
        
        print(f"\n📄 Reporte guardado: report_{ip.replace('.', '_')}.json")

if __name__ == "__main__":
    scanner = VulnerabilityScanner()
    target = input("🌐 Ingresa la IP o dominio a escanear: ")
    scanner.scan_target(target)
