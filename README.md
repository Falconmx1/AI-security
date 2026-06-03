<p align="center">
  <img src="https://raw.githubusercontent.com/Falconmx1/AI-security/main/banner-tortuga.png" alt="Tortuga Security AI" width="400">
  <br>
  <strong style="font-size: 32px;">🐢 Security AI</strong>
  <br>
  <em>Protección con caparazón duro - Ciberseguridad con IA</em>
</p>

# 🔒 Security AI - La Tortuga Más Chingona de la Ciberseguridad

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![GitHub stars](https://img.shields.io/github/stars/Falconmx1/AI-security)](https://github.com/Falconmx1/AI-security/stargazers)

**Herramienta de ciberseguridad TODO EN UNO con inteligencia artificial.**  
Análisis de malware, detección de intrusos, scanning de vulnerabilidades, análisis de tráfico de red, cryptojacking y ransomware detection.  
**Sin Ollama, sin pedos, pura tortuga power** 🐢🔥

---

## ⚡ Características Principales

### 🦠 **Detección de Malware**
- Análisis por hash (firmas MD5)
- Heurística avanzada con entropía y strings sospechosos
- Modelo Naive Bayes para clasificación
- Cuarentena automática

### 🔍 **Escáner de Vulnerabilidades**
- Escaneo de puertos multi-thread
- Detección de servicios vulnerables
- Base de datos de CVEs conocidos
- Reportes JSON detallados

### 👁️ **IDS (Sistema de Detección de Intrusos)**
- Monitoreo de conexiones en tiempo real
- Detección de escaneos de puertos
- Fuerza bruta en logs de autenticación
- Bloqueo automático de IPs

### 🌐 **Network Traffic Analyzer**
- Captura y análisis de paquetes en vivo
- Detección de DDoS
- DNS malicioso y DGA
- Payloads HTTP maliciosos (SQLi, comandos)
- ICMP tunneling

### ⛏️ **Cryptojacking Detection**
- Monitoreo de CPU/Memoria por proceso
- Patrones de minería de criptomonedas
- Conexiones a pools de minería
- Picos anormales de rendimiento

### 💀 **Ransomware Behavior Detection**
- Detección de comandos típicos (vssadmin, cipher)
- Renombrado masivo de archivos
- Extensiones ransomware conocidas
- Aislamiento automático del sistema

### 🤖 **Respuesta Automática**
- Cuarentena de archivos maliciosos
- Terminación de procesos sospechosos
- Bloqueo de IPs en firewall
- Aislamiento de red en ransomware

---

## 🚀 Instalación Rápida

```bash
# Clonar el repositorio
git clone https://github.com/Falconmx1/AI-security.git
cd AI-security

# Instalar dependencias
pip install -r requirements.txt

# Dar permisos de ejecución (Linux/Mac)
chmod +x main.py

# Ejecutar (como administrador/root para funciones completas)
sudo python main.py --all

📖 Modos de Uso
🎯 Modo Todo en Uno (Recomendado)
sudo python main.py --all
Activa IDS + Network Analyzer + Responder + Behavior Analyzer

🔍 Escáner de Vulnerabilidades
python main.py --scan 192.168.1.1
python main.py --scan google.com

🦠 Análisis de Malware
python main.py --malware archivo_sospechoso.exe

🛡️ Solo IDS
sudo python main.py --ids

🌐 Solo Análisis de Red
sudo python main.py --network
sudo python main.py --network --interface eth0

⛏️ Detección de Cryptojacking/Ransomware
sudo python main.py --behavior

🎮 Modo Interactivo
python main.py
# Luego elige opción del menú
