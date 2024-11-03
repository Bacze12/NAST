# modules/utils/crypto.py
import hashlib
import base64
from cryptography.fernet import Fernet
from typing import Optional
import logging

class CryptoUtils:
    """Utilidades criptográficas"""
    
    @staticmethod
    def hash_data(data: str, algorithm: str = 'sha256') -> str:
        """Genera hash de datos"""
        if algorithm == 'md5':
            return hashlib.md5(data.encode()).hexdigest()
        elif algorithm == 'sha1':
            return hashlib.sha1(data.encode()).hexdigest()
        else:
            return hashlib.sha256(data.encode()).hexdigest()
            
    @staticmethod
    def generate_key() -> bytes:
        """Genera clave para cifrado"""
        return Fernet.generate_key()
        
    @staticmethod
    def encrypt_data(data: str, key: bytes) -> str:
        """Cifra datos"""
        f = Fernet(key)
        return f.encrypt(data.encode()).decode()
        
    @staticmethod
    def decrypt_data(encrypted_data: str, key: bytes) -> Optional[str]:
        """Descifra datos"""
        try:
            f = Fernet(key)
            return f.decrypt(encrypted_data.encode()).decode()
        except:
            return None