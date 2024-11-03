# modules/network/anonymizer.py
import subprocess
import random
import netifaces
import ipaddress
import logging
from typing import Optional
import time

class NetworkAnonymizer:
    """Gestor de anonimización de red"""
    
    def __init__(self):
        self.logger = logging.getLogger('NetworkAnonymizer')
        self.original_configs = {}
        
    def anonymize(self, interface: str) -> bool:
        """Anonimiza interfaz de red"""
        try:
            # Guardar configuración original
            self._backup_config(interface)
            
            # Desactivar interfaz
            self._toggle_interface(interface, False)
            
            # Cambiar MAC
            new_mac = self._generate_safe_mac()
            if not self._change_mac(interface, new_mac):
                raise Exception("Failed to change MAC")
                
            # Cambiar IP
            new_ip = self._generate_safe_ip(interface)
            if not self._change_ip(interface, new_ip):
                raise Exception("Failed to change IP")
                
            # Reactivar interfaz
            self._toggle_interface(interface, True)
            
            return True
            
        except Exception as e:
            self.logger.error(f"Anonymization error: {e}")
            self._restore_original(interface)
            return False
            
    def _generate_safe_mac(self) -> str:
        """Genera MAC address segura"""
        mac = [random.randint(0x00, 0xff) for _ in range(6)]
        return ':'.join([f"{x:02x}" for x in mac])
        
    def _generate_safe_ip(self, interface: str) -> str:
        """Genera IP segura dentro de la subred"""
        try:
            addrs = netifaces.ifaddresses(interface)
            current_ip = addrs[netifaces.AF_INET][0]['addr']
            netmask = addrs[netifaces.AF_INET][0]['netmask']
            
            network = ipaddress.IPv4Network(f'{current_ip}/{netmask}', strict=False)
            available_ips = list(network.hosts())
            
            return str(random.choice(available_ips))
            
        except Exception as e:
            self.logger.error(f"IP generation error: {e}")
            raise
            
    def _change_mac(self, interface: str, new_mac: str) -> bool:
        """Cambia MAC address"""
        try:
            subprocess.run(['ip', 'link', 'set', interface, 'address', new_mac],
                         check=True)
            return True
        except subprocess.CalledProcessError:
            return False
            
    def _change_ip(self, interface: str, new_ip: str) -> bool:
        """Cambia dirección IP"""
        try:
            subprocess.run(['ip', 'addr', 'add', new_ip, 'dev', interface],
                         check=True)
            return True
        except subprocess.CalledProcessError:
            return False
            
    def _toggle_interface(self, interface: str, up: bool):
        """Activa/desactiva interfaz"""
        try:
            action = 'up' if up else 'down'
            subprocess.run(['ip', 'link', 'set', interface, action], check=True)
            if up:
                time.sleep(2)  # Esperar a que la interfaz esté lista
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Interface toggle error: {e}")
            raise
            
    def _backup_config(self, interface: str):
        """Guarda configuración original"""
        try:
            self.original_configs[interface] = {
                'mac': self._get_current_mac(interface),
                'ip': self._get_current_ip(interface)
            }
        except Exception as e:
            self.logger.error(f"Backup config error: {e}")
            raise
            
    def _restore_original(self, interface: str):
        """Restaura configuración original"""
        if interface in self.original_configs:
            config = self.original_configs[interface]
            try:
                self._toggle_interface(interface, False)
                if config['mac']:
                    self._change_mac(interface, config['mac'])
                if config['ip']:
                    self._change_ip(interface, config['ip'])
                self._toggle_interface(interface, True)
            except Exception as e:
                self.logger.error(f"Restore config error: {e}")
                raise
