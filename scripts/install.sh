#!/bin/bash
# scripts/install.sh

echo "=== NAST Installation Script ==="

# Verificar Python y crear venv
python3 -m venv venv
source venv/bin/activate

# Instalar dependencias principales
pip install --upgrade pip
pip install -r requirements.txt

# Ejecutar configuración inicial
python3 -c "
from config.paths import Paths
Paths.create_required_directories()
"

echo "Installation completed! Run 'source scripts/setup_env.sh' to configure the environment."