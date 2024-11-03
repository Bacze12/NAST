# NAST (Network Analysis & Security Tool)

## Descripción
NAST es una herramienta avanzada de análisis de seguridad y red que combina capacidades de reconocimiento, análisis y evaluación de seguridad. Diseñada para ser sigilosa y eficiente en pruebas de penetración, CTFs y análisis de red empresarial.

## 📋 Características Principales

### 🔍 Análisis de Red
- Escaneo sigiloso con múltiples técnicas de evasión
- Detección precisa de servicios y versiones
- Mapeo de red y topología
- Cambio automático de identidad (MAC/IP)

### 🌐 Reconocimiento
- Enumeración de subdominios
- OSINT integrado
- Detección de tecnologías web
- Fingerprinting de servicios

### 🚨 Análisis de Vulnerabilidades
- Detección de configuraciones erróneas
- Verificación de vulnerabilidades web
- Análisis de servicios desactualizados
- Comprobación SSL/TLS

### 📊 Análisis de Tráfico
- Captura y análisis en tiempo real
- Detección de patrones maliciosos
- Inspección de paquetes
- Identificación de anomalías

### 🎯 CTF
- Resolución automática de retos web
- Decodificación múltiple formatos
- Análisis de vulnerabilidades comunes
- Extracción de datos ocultos

## 🚀 Instalación

```bash
# Clonar repositorio
git clone https://github.com/yourusername/nast.git
cd nast

# Instalar
./scripts/install.sh

# Configurar entorno
source scripts/setup_env.sh
```

## 📖 Uso

### Escaneo Básico
```bash
# Escaneo sigiloso
python nast.py --target 192.168.1.0/24 --mode stealth

# Análisis completo
python nast.py --target 192.168.1.0/24 --mode full --output report.html
```

### Análisis Web
```bash
# Escaneo web
python nast.py --target http://example.com --mode web

# Búsqueda de vulnerabilidades
python nast.py --target http://example.com --mode vuln
```

### CTF
```bash
# Análisis automático
python nast.py --target http://ctf.example.com --mode ctf

# Decodificación
python nast.py --file encoded.txt --mode decode
```

## 📁 Estructura del Proyecto
```
nast/
├── config/           # Configuración centralizada
├── modules/          # Módulos principales
│   ├── network/      # Gestión de red
│   ├── recon/        # Reconocimiento
│   ├── vuln/         # Análisis vulnerabilidades
│   ├── traffic/      # Análisis tráfico
│   ├── ctf/          # Módulo CTF
│   └── report/       # Generación reportes
├── data/             # Datos y recursos
└── scripts/          # Scripts de utilidad
```

## ⚙️ Configuración
La configuración se maneja de forma centralizada en:
- `config/settings.py`: Configuraciones globales
- `config/paths.py`: Gestión de rutas

## 🛠️ Requisitos
- Python 3.8+
- Permisos de red (para algunas funciones)
- Dependencias en requirements.txt

## 🚦 Estados de Ejecución

### Modo Sigiloso
```bash
python nast.py --mode stealth --target [objetivo]
```
- Técnicas de evasión avanzadas
- Distribución temporal de operaciones
- Cambio automático de identidad

### Modo Rápido
```bash
python nast.py --mode fast --target [objetivo]
```
- Escaneo rápido
- Sin técnicas de evasión
- Resultados inmediatos

### Modo CTF
```bash
python nast.py --mode ctf --target [objetivo]
```
- Enfocado en retos CTF
- Decodificación automática
- Búsqueda de flags

## 📝 Reportes
Los reportes se generan en múltiples formatos:
- HTML: Reportes interactivos
- JSON: Datos estructurados
- Markdown: Documentación legible

## 🔄 Actualización
```bash
./scripts/update.sh
```

## 🤝 Contribuir
1. Fork del repositorio
2. Crear rama de feature (`git checkout -b feature/nombre`)
3. Commit cambios (`git commit -am 'Add: característica'`)
4. Push a la rama (`git push origin feature/nombre`)
5. Crear Pull Request

## 📄 Licencia
MIT License - Ver LICENSE para más detalles

## ⚠️ Aviso Legal
Esta herramienta es para propósitos educativos y pruebas autorizadas. El uso indebido puede ser ilegal.

## 🔧 Solución de Problemas

### Problemas Comunes
1. Error de permisos:
```bash
sudo setcap cap_net_raw+ep venv/bin/python3
```

2. Error de dependencias:
```bash
pip install -r requirements.txt --upgrade
```

3. Error de configuración:
```bash
source scripts/setup_env.sh
```

## 📚 Documentación Adicional
Para más información sobre:
- [Guía de Desarrollo](docs/DEVELOPMENT.md)
- [Guía de Contribución](docs/CONTRIBUTING.md)
- [Documentación de la API](docs/API.md)