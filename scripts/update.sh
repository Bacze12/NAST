#!/bin/bash
# scripts/update.sh

# Activar venv
source venv/bin/activate

# Actualizar código
git pull origin main

# Actualizar dependencias
pip install -r requirements.txt --upgrade

# Verificar estructura
python3 -c "
from config.paths import Paths
Paths.create_required_directories()
"

echo "Update completed successfully!"