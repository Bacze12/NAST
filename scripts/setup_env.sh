#!/bin/bash
# scripts/setup_env.sh

# Activar venv si no está activo
if [ -z "$VIRTUAL_ENV" ]; then
    source venv/bin/activate
fi

# Configurar variables de entorno usando Python
python3 -c "
from config.settings import BASE_DIR
print(f'export NAST_HOME={BASE_DIR}')
print(f'export PYTHONPATH={BASE_DIR}:$PYTHONPATH')
" > .env

source .env

echo "Environment configured successfully!"