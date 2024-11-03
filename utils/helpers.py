# modules/utils/helpers.py
import os
import json
import logging
from typing import Any, Dict, Optional
from datetime import datetime

class Helpers:
    """Funciones auxiliares generales"""
    
    @staticmethod
    def load_json_file(filepath: str) -> Optional[Dict]:
        """Carga archivo JSON"""
        try:
            with open(filepath, 'r') as f:
                return json.load(f)
        except Exception as e:
            logging.error(f"Error loading JSON file: {e}")
            return None
            
    @staticmethod
    def save_json_file(data: Any, filepath: str) -> bool:
        """Guarda datos en archivo JSON"""
        try:
            with open(filepath, 'w') as f:
                json.dump(data, f, indent=4)
            return True
        except Exception as e:
            logging.error(f"Error saving JSON file: {e}")
            return False
            
    @staticmethod
    def ensure_dir(directory: str):
        """Asegura que directorio existe"""
        if not os.path.exists(directory):
            os.makedirs(directory)
            
    @staticmethod
    def generate_filename(prefix: str, ext: str) -> str:
        """Genera nombre de archivo con timestamp"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        return f"{prefix}_{timestamp}.{ext}"