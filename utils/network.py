# modules/utils/network.py
import socket
import struct
import fcntl
import netifaces
from typing import Optional, List, Dict
import logging

class NetworkUtils:
    """Utilidades de red"""
    
    @staticmethod
    def get_interface_ip(interface: str) -> Optional[str]:
        """Obtiene IP de interfaz"""
        try:
            return netifaces.ifaddresses(interface)[netifaces.AF_INET][0]['addr']
        except:
            return None
            
    @staticmethod
    def get_interface_mac(interface: str) -> Optional[str]:
        """Obtiene MAC de interfaz"""
        try:
            with open(f'/sys/class/net/{interface}/address') as f:
                return f.read().strip()
        except:
            return None
            
    @staticmethod
    def get_default_gateway() -> Optional[str]:
        """Obtiene gateway por defecto"""
        try:
            gws = netifaces.gateways()
            return gws['default'][netifaces.AF_INET][0]
        except:
            return None
            
    @staticmethod
    def is_port_open(host: str, port: int) -> bool:
        """Verifica si puerto está abierto"""
        try:
            sock = socket.create_connection((host, port), timeout=2)
            sock.close()
            return True
        except:
            return False