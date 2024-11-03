import os
from pathlib import Path

# Directorios base
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / 'data'
WORDLIST_DIR = DATA_DIR / 'wordlists'
SIGNATURE_DIR = DATA_DIR / 'signatures'
REPORT_DIR = DATA_DIR / 'reports'
BACKUP_DIR = DATA_DIR / 'backups'

# Configuración de la aplicación
APP_NAME = 'NAST'
VERSION = '1.0.0'
DEBUG = False
LOGGING_LEVEL = 'INFO'

# Configuración de red
NETWORK_SETTINGS = {
    'timeout': 5,
    'retries': 3,
    'stealth_level': 3,
    'required_tools': [
        'nmap',
        'tcpdump',
        'wireshark'
    ]
}

# Configuración de instalación
INSTALL_SETTINGS = {
    'required_packages': [
        'scapy',
        'python-nmap',
        'requests',
        'aiohttp',
        'beautifulsoup4'
    ],
    'directories': [
        'data/wordlists',
        'data/signatures',
        'data/reports',
        'data/backups'
    ],
    'permissions': {
        'scripts': 0o755,
        'configs': 0o644
    }
}

# Configuración de base de datos
DATABASE = {
    'path': DATA_DIR / 'nast.db',
    'backup_path': BACKUP_DIR / 'db_backups'
}

# Configuración de logging
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'standard': {
            'format': '%(asctime)s [%(levelname)s] %(name)s: %(message)s'
        },
    },
    'handlers': {
        'file': {
            'class': 'logging.FileHandler',
            'filename': DATA_DIR / 'nast.log',
            'formatter': 'standard'
        },
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'standard'
        }
    },
    'loggers': {
        '': {
            'handlers': ['file', 'console'],
            'level': LOGGING_LEVEL
        }
    }
}