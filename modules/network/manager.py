# modules/network/manager.py
import netifaces
import socket
import struct
import fcntl
import os
import time
import random
import logging
import ipaddress
from typing import Dict, List, Optional
from ..core.exceptions import NetworkError
from .scanner import StealthScanner
from .anonymizer import NetworkAnonymizer

class NetworkManager:
    """Gestor principal de red"""
    
    def __init__(self, interface: str = None):
        self.interface = interface
        self.logger = logging.getLogger('NetworkManager')
        self.scanner = StealthScanner()
        self.anonymizer = NetworkAnonymizer()
        self.initialize()
        
    def initialize(self):
        """Inicializa componentes de red"""
        self.interfaces = self._get_interfaces()
        if self.interface and self.interface not in self.interfaces:
            raise NetworkError(f"Interface {self.interface} not found")
            
    def _get_interfaces(self) -> Dict[str, Dict]:
        """Obtiene información de interfaces"""
        interfaces = {}
        for iface in netifaces.interfaces():
            try:
                interfaces[iface] = {
                    'mac': self._get_mac(iface),
                    'ip': self._get_ip(iface),
                    'netmask': self._get_netmask(iface),
                    'broadcast': self._get_broadcast(iface)
                }
            except Exception as e:
                self.logger.error(f"Error getting interface {iface} info: {e}")
        return interfaces
        
    def _get_mac(self, iface: str) -> str:
        """Obtiene MAC address"""
        try:
            with open(f'/sys/class/net/{iface}/address') as f:
                return f.read().strip()
        except:
            return None
            
    def _get_ip(self, iface: str) -> str:
        """Obtiene dirección IP"""
        try:
            return netifaces.ifaddresses(iface)[netifaces.AF_INET][0]['addr']
        except:
            return None
            
    def scan_network(self, target: str, ports: List[int] = None,
                    stealth: bool = True) -> Dict:
        """Escanea red objetivo"""
        try:
            return self.scanner.scan(target, ports, stealth)
        except Exception as e:
            self.logger.error(f"Scan error: {e}")
            raise NetworkError(f"Scan failed: {e}")
            
    def enable_anonymous_mode(self) -> bool:
        """Activa modo anónimo"""
        if not self.interface:
            raise NetworkError("No interface specified")
        return self.anonymizer.anonymize(self.interface)